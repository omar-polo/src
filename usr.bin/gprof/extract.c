/*	$OpenBSD$	*/
/*
 * Copyright (c) 2023 Sebastien Marie <semarie@openbsd.org>
 * Copyright (c) 2023 Scott Cheloha <cheloha@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/gmon.h>
#include <sys/ktrace.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GMON_LABEL	"_openbsd_libc_gmon"
#define GMON_LABEL_LEN	(sizeof(GMON_LABEL) - 1)

/*
 * A rudimentary gmon.out deserialization state machine.
 * Allows for basic error-checking and the detection of an
 * incomplete record set.
 */
enum gmon_state {
	HEADER,
	KCOUNT,
	RAWARC,
	FOOTER,
	ERROR
};

struct gmon_de {
	size_t sample_count;	/* kcount array: current sample count */ 
	size_t sample_total;	/* kcount array: total samples in array */
	enum gmon_state state;	/* gmon.out deserialization step */
};

void de_warnx(const char *, const char *, ...);
void gmon_append(FILE *, const char *, struct gmon_de *, const char *, char *);
int ktrace_header(FILE *, struct ktr_header *);
int ktrace_next(FILE *, const char *, struct ktr_header *, void **, size_t *);

extern pid_t target_pid;

FILE *
ktrace_extract(FILE *kfp, const char *ktrace_path)
{
	struct _user_trace {
		struct ktr_user hdr;
		char buf[KTR_USER_MAXLEN + 1];	/* +1 for NUL */
	} *user_trace;
	char temp_path[32];
	struct gmon_de de = { .state = HEADER };
	struct ktr_header header = { 0 };
	FILE *tfp;
	void *buf = NULL, *label;
	size_t buf_size = 0, len;
	int fd, have_pid = 0, saved_errno;
	pid_t pid;

	/* Deserialize moncontrol(3) records into a temporary file. */
	len = strlcpy(temp_path, "/tmp/gmon.out.XXXXXXXXXX", sizeof temp_path);
	assert(len < sizeof temp_path);
	fd = mkstemp(temp_path);
	if (fd == -1) {
		warn("mkstemp");
		return NULL;
	}

	/*
	 * We have opened a file descriptor.  From this point on,
	 * we need to to jump to "error" and clean up before returning.
	 */
	if (unlink(temp_path) == -1) {
		warn("unlink: %s", temp_path);
		goto error;
	}
	tfp = fdopen(fd, "r+");
	if (tfp == NULL) {
		warn("%s", temp_path);
		goto error;
	}

	if (ktrace_header(kfp, &header) == -1) {
		warn("%s", ktrace_path);
		goto error;
	}
	if (header.ktr_type != htobe32(KTR_START)) {
		warn("%s: not a valid ktrace file", ktrace_path);
		goto error;
	}

	while (ktrace_next(kfp, ktrace_path, &header, &buf, &buf_size) != -1) {
		/* Filter for utrace(2) headers with the gmon label. */
		if (header.ktr_type != KTR_USER)
			continue;
		user_trace = buf;
		label = &user_trace->hdr.ktr_id;
		if (memcmp(label, GMON_LABEL, GMON_LABEL_LEN) != 0)
			continue;

		/* Only consider the first gmon.out record set. */
		if (!have_pid) {
			if (target_pid != -1 && header.ktr_pid != target_pid)
				continue;
			pid = header.ktr_pid;
			have_pid = 1;
		}
		if (have_pid && pid != header.ktr_pid)
			continue;

		/* Append the next piece. */
		gmon_append(tfp, temp_path, &de, ktrace_path, user_trace->buf);
		if (de.state == FOOTER || de.state == ERROR)
			break;
	}
	if (ferror(kfp)) {
		warn("%s", ktrace_path);
		goto error;
	}

	if (de.state == ERROR)
		goto error;
	if (de.state == HEADER) {
		warnx("%s: no moncontrol record set found", ktrace_path);
		goto error;
	}
	if (de.state != FOOTER) {
		warnx("%s: found incomplete moncontrol record set",
		    ktrace_path);
		goto error;
	}

	/*
	 * We have a complete gmon.out file.  Flush and rewind the
	 * handle so the caller can reread it.
	 */
	if (fflush(tfp) == EOF) {
		warn("%s", temp_path);
		goto error;
	}
	if (fseek(tfp, 0, SEEK_SET) == -1) {
		warn("%s", temp_path);
		goto error;
	}

	return tfp;
error:
	free(buf);
	saved_errno = errno;
	if (close(fd) == -1)
		warn("close: %s", temp_path);
	errno = saved_errno;
	return NULL;
}

void
de_warnx(const char *ktrace_path, const char *fmt, ...)
{
	int saved_errno = errno;
	va_list ap;

	fprintf(stderr, "%s: %s: deserialization failed: ",
	    getprogname(), ktrace_path);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	errno = saved_errno;
}

void
gmon_append(FILE *fp, const char *path, struct gmon_de *de,
    const char *ktrace_path, char *trace)
{
	struct gmonhdr header;
	struct rawarc arc;
	char *p;
	int count;
	uint16_t sample;

	switch (de->state) {
	case HEADER:
		memset(&header, 0, sizeof header);
		count = sscanf(trace, "gmonhdr %lx %lx %x %x %x",
		    &header.lpc, &header.hpc, &header.ncnt, &header.version,
		    &header.profrate);
		if (count != 5) {
			de_warnx(ktrace_path, "gmonhdr: %s", trace);
			goto error;
		}
		if (header.ncnt < sizeof header) {
			de_warnx(ktrace_path, "gmonhdr: ncnt is invalid: %d",
			    header.ncnt);
			goto error;
		}
		if (fwrite(&header, sizeof header, 1, fp) != 1) {
			warn("%s", path);
			goto error;
		}
		de->sample_count = 0;
		de->sample_total = (header.ncnt - sizeof(header)) / 2;
		de->state = KCOUNT;
		return;
	case KCOUNT:
		p = strsep(&trace, " ");
		if (p == NULL || strcmp(p, "kcount") != 0) {
			de_warnx(ktrace_path, "kcount: %s",
			    p == NULL ? trace : p);
			goto error;
		}
		while ((p = strsep(&trace, " ")) != NULL) {
			if (strlen(p) != 4) {
				de_warnx(ktrace_path,
				    "kcount: sample %zu/%zu is invalid: %s",
				    de->sample_count, de->sample_total, p);
				goto error;
			}
			if (de->sample_count == de->sample_total) {
				de_warnx(ktrace_path,
				    "kcount: found more than %zu samples",
				    de->sample_total);
				goto error;
			}
			sample = 0;
			for (; *p != '\0'; p++) {
				if (*p < '0' || 'f' < *p) {
					de_warnx(ktrace_path, "kcount: "
					    "sample %zu/%zu is invalid: %s",
					    de->sample_count,
					    de->sample_total, p);
					goto error;
				}
				sample = sample * 16 + (*p - '0');
			}
			if (fwrite(&sample, sizeof sample, 1, fp) != 1) {
				warn("%s", path);
				goto error;
			}
			de->sample_count++;
		}
		if (de->sample_count == de->sample_total)
			de->state = RAWARC;
		return;
	case RAWARC:
		if (strcmp(trace, "footer") == 0) {
			de->state = FOOTER;
			return;
		}
		memset(&arc, 0, sizeof arc);
		count = sscanf(trace, "rawarc %lx %lx %lx",
		    &arc.raw_frompc, &arc.raw_selfpc, &arc.raw_count);
		if (count != 3) {
			de_warnx(ktrace_path, "rawarc: %s", trace);
			goto error;
		}
		if (fwrite(&arc, sizeof arc, 1, fp) != 1) {
			warn("%s", path);
			goto error;
		}
		return;
	case FOOTER:
	case ERROR:
	default:
		abort();
	}

error:
	de->state = ERROR;
}

int
ktrace_header(FILE *fp, struct ktr_header *header)
{
	if (fread(header, sizeof(*header), 1, fp) == 1)
		return 0;
	return -1;
}

int
ktrace_next(FILE *fp, const char *ktrace_path, struct ktr_header *header,
    void **bufp, size_t *sizep)
{
	void *new_buf;
	size_t new_size;

	if (ktrace_header(fp, header) == -1)
		return -1;
	if (header->ktr_len == 0)
		errx(1, "%s: invalid trace: ktr_len is zero", ktrace_path);
	if (header->ktr_len > *sizep) {
		new_size = header->ktr_len + 1;		/* +1 for NUL */
		new_buf = realloc(*bufp, new_size);
		if (new_buf == NULL)
			err(1, NULL);
		*bufp = new_buf;
		*sizep = new_size;
	}
	memset(*bufp, 0, *sizep);
	if (fread(*bufp, header->ktr_len, 1, fp) != 1)
		return -1;
	return 0;
}

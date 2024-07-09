/*	$OpenBSD: gmon.c,v 1.33 2022/07/26 04:07:13 cheloha Exp $ */
/*-
 * Copyright (c) 1983, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/gmon.h>
#include <sys/ktrace.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>

struct gmonparam _gmonparam = { GMON_PROF_OFF };

static int	s_scale;
/* see profil(2) where this is describe (incorrectly) */
#define		SCALE_1_TO_1	0x10000L

#define ERR(s) write(STDERR_FILENO, s, sizeof(s))
#define GMON_LABEL	"_openbsd_libc_gmon"

PROTO_NORMAL(moncontrol);
PROTO_DEPRECATED(monstartup);

void
monstartup(u_long lowpc, u_long highpc)
{
	int o;
	void *addr;
	struct gmonparam *p = &_gmonparam;

	/*
	 * round lowpc and highpc to multiples of the density we're using
	 * so the rest of the scaling (here and in gprof) stays in ints.
	 */
	p->lowpc = ROUNDDOWN(lowpc, HISTFRACTION * sizeof(HISTCOUNTER));
	p->highpc = ROUNDUP(highpc, HISTFRACTION * sizeof(HISTCOUNTER));
	p->textsize = p->highpc - p->lowpc;
	p->kcountsize = p->textsize / HISTFRACTION;
	p->hashfraction = HASHFRACTION;
	p->fromssize = p->textsize / p->hashfraction;
	p->tolimit = p->textsize * ARCDENSITY / 100;
	if (p->tolimit < MINARCS)
		p->tolimit = MINARCS;
	else if (p->tolimit > MAXARCS)
		p->tolimit = MAXARCS;
	p->tossize = p->tolimit * sizeof(struct tostruct);

	addr = mmap(NULL, p->kcountsize,  PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED)
		goto mapfailed;
	p->kcount = addr;

	addr = mmap(NULL, p->fromssize,  PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED)
		goto mapfailed;
	p->froms = addr;

	addr = mmap(NULL, p->tossize,  PROT_READ|PROT_WRITE,
	    MAP_ANON|MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED)
		goto mapfailed;
	p->tos = addr;
	p->tos[0].link = 0;

	o = p->highpc - p->lowpc;
	if (p->kcountsize < o) {
#ifndef notdef
		s_scale = ((float)p->kcountsize / o ) * SCALE_1_TO_1;
#else /* avoid floating point */
		int quot = o / p->kcountsize;

		if (quot >= 0x10000)
			s_scale = 1;
		else if (quot >= 0x100)
			s_scale = 0x10000 / quot;
		else if (o >= 0x800000)
			s_scale = 0x1000000 / (o / (p->kcountsize >> 8));
		else
			s_scale = 0x1000000 / ((o << 8) / p->kcountsize);
#endif
	} else
		s_scale = SCALE_1_TO_1;

	moncontrol(1);
	return;

mapfailed:
	if (p->kcount != NULL) {
		munmap(p->kcount, p->kcountsize);
		p->kcount = NULL;
	}
	if (p->froms != NULL) {
		munmap(p->froms, p->fromssize);
		p->froms = NULL;
	}
	if (p->tos != NULL) {
		munmap(p->tos, p->tossize);
		p->tos = NULL;
	}
	ERR("monstartup: out of memory\n");
}
__strong_alias(_monstartup,monstartup);

void
_mcleanup(void)
{
	char ubuf[KTR_USER_MAXLEN + 1];	/* +1 for NUL, for snprintf(3) */
	int error, fromindex, len;
	int endfrom;
	u_long frompc, i, j, limit;
	int toindex;
	struct rawarc rawarc;
	struct gmonparam *p = &_gmonparam;
	struct gmonhdr gmonhdr, *hdr;
	struct clockinfo clockinfo;
	const int mib[2] = { CTL_KERN, KERN_CLOCKRATE };
	size_t off, sample_limit, sample_total, size;

	if (p->state == GMON_PROF_ERROR)
		ERR("_mcleanup: tos overflow\n");

	/*
	 * There is nothing we can do if sysctl(2) fails or if
	 * clockinfo.hz is unset.
	 */
	size = sizeof(clockinfo);
	if (sysctl(mib, 2, &clockinfo, &size, NULL, 0) == -1) {
		clockinfo.profhz = 0;
	} else if (clockinfo.profhz == 0) {
		clockinfo.profhz = clockinfo.hz;	/* best guess */
	}

	moncontrol(0);

	/* First, serialize the gmon header. */
	hdr = (struct gmonhdr *)&gmonhdr;
	bzero(hdr, sizeof(*hdr));
	hdr->lpc = p->lowpc;
	hdr->hpc = p->highpc;
	hdr->ncnt = p->kcountsize + sizeof(gmonhdr);
	hdr->version = GMONVERSION;
	hdr->profrate = clockinfo.profhz;
	len = snprintf(ubuf, sizeof ubuf, "gmonhdr %lx %lx %x %x %x",
	    hdr->lpc, hdr->hpc, hdr->ncnt, hdr->version, hdr->profrate);
	if (len == -1 || len >= sizeof ubuf)
		goto out;
	if (utrace(GMON_LABEL, ubuf, len) == -1)
		goto out;

	/*
	 * Next, serialize the kcount sample array.  Each trace is prefixed
	 * with the string "kcount" (6).  Each sample is prefixed with a
	 * delimiting space (1) and serialized as a 4-digit hexadecimal
	 * value (4).  The buffer, ubuf, is KTR_USER_MAXLEN + 1 bytes, but
	 * each trace is limited to KTR_USER_MAXLEN bytes.  Given these
	 * constraints, we can fit at most:
	 *
	 *	  floor((KTR_USER_MAXLEN - 6) / (4 + 1)
	 *	= floor((KTR_USER_MAXLEN - 6) / 5)
	 *
	 * samples per trace.
	 */
	assert(sizeof(*p->kcount) == 2);
	sample_total = p->kcountsize / sizeof(*p->kcount);
	sample_limit = (sizeof(ubuf) - 6) / 5;
	for (i = 0; i < sample_total; i = j) {
		off = strlcpy(ubuf, "kcount", sizeof ubuf);
		assert(off == 6);
		if (sample_total - i < sample_limit)
			limit = sample_total;
		else
			limit = i + sample_limit;
		for (j = i; j < limit; j++) {
			len = snprintf(ubuf + off, sizeof(ubuf) - off,
			    " %04hx", p->kcount[j]);
			assert(len == 5);
			off += len;
			assert(off < sizeof ubuf);
		}
		if (utrace(GMON_LABEL, ubuf, off) == -1)
			goto out;
	}

	/* Last, serialize the arcs.  One per trace. */
	endfrom = p->fromssize / sizeof(*p->froms);
	for (fromindex = 0; fromindex < endfrom; fromindex++) {
		if (p->froms[fromindex] == 0)
			continue;

		frompc = p->lowpc;
		frompc += fromindex * p->hashfraction * sizeof(*p->froms);
		for (toindex = p->froms[fromindex]; toindex != 0;
		     toindex = p->tos[toindex].link) {
			rawarc.raw_frompc = frompc;
			rawarc.raw_selfpc = p->tos[toindex].selfpc;
			rawarc.raw_count = p->tos[toindex].count;
			len = snprintf(ubuf, sizeof ubuf, "rawarc %lx %lx %lx",
			    rawarc.raw_frompc, rawarc.raw_selfpc,
			    rawarc.raw_count);
			if (len == -1 || len >= sizeof ubuf)
				goto out;
			if (utrace(GMON_LABEL, ubuf, len) == -1)
				goto out;
		}
	}

	/*
	 * Leave a footer so the reader knows they have the full dump.
	 * This is a convenience for the reader: it is not a part of
	 * the gmon binary.
	 */
	off = strlcpy(ubuf, "footer", sizeof ubuf);
	assert(off == 6);
	utrace(GMON_LABEL, ubuf, off);
out:
	/* nothing */;
#ifdef notyet
	if (p->kcount != NULL) {
		munmap(p->kcount, p->kcountsize);
		p->kcount = NULL;
	}
	if (p->froms != NULL) {
		munmap(p->froms, p->fromssize);
		p->froms = NULL;
	}
	if (p->tos != NULL) {
		munmap(p->tos, p->tossize);
		p->tos = NULL;
	}
#endif
}

/*
 * Control profiling
 *	profiling is what mcount checks to see if
 *	all the data structures are ready.
 */
void
moncontrol(int mode)
{
	struct gmonparam *p = &_gmonparam;

	if (mode) {
		/* start */
		profil((char *)p->kcount, p->kcountsize, p->lowpc,
		    s_scale);
		p->state = GMON_PROF_ON;
	} else {
		/* stop */
		profil(NULL, 0, 0, 0);
		p->state = GMON_PROF_OFF;
	}
}
DEF_WEAK(moncontrol);

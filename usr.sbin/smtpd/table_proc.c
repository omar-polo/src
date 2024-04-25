/*	$OpenBSD: table_proc.c,v 1.17 2021/06/14 17:58:16 eric Exp $	*/

/*
 * Copyright (c) 2024 Omar Polo <op@openbsd.org>
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtpd.h"
#include "log.h"

#define PROTOCOL_VERSION	"0.1"

struct table_proc_priv {
	pid_t		 pid;
	char		 lastid[32];
	FILE		*fp;
	char		*line;
	size_t		 linesize;
};

static char *
table_proc_nextid(struct table *table)
{
	struct table_proc_priv	*priv = table->t_handle;
	int			 r;

	r = snprintf(priv->lastid, sizeof(priv->lastid), "%lld",
	    (unsigned long long)arc4random());
	if (r < 0 || (size_t)r >= sizeof(priv->lastid))
		fatal("table-proc: snprintf");

	return (priv->lastid);
}

static void
table_proc_send(struct table *table, const char *type, int service,
    const char *param)
{
	struct table_proc_priv	*priv = table->t_handle;
	struct timeval		 tv;

	gettimeofday(&tv, NULL);
	fprintf(priv->fp, "table|%s|%lld.%06ld|%s|%s",
	    PROTOCOL_VERSION, (long long)tv.tv_sec, (long)tv.tv_usec,
	    table->t_name, type);
	if (service != -1) {
		fprintf(priv->fp, "|%s|%s", table_service_name(service),
		    table_proc_nextid(table));
		if (param)
			fprintf(priv->fp, "|%s", param);
		fputc('\n', priv->fp);
	} else
		fprintf(priv->fp, "|%s\n", table_proc_nextid(table));

	if (fflush(priv->fp) == EOF)
		fatal("table-proc: fflush");
}

static const char *
table_proc_recv(struct table *table, const char *type)
{
	struct table_proc_priv	*priv = table->t_handle;
	const char		*l;
	ssize_t			 linelen;
	size_t			 len;

	if ((linelen = getline(&priv->line, &priv->linesize, priv->fp)) == -1)
		fatal("table-proc: getline");
	if (priv->line[linelen - 1] == '\n')
		priv->line[--linelen] = '\0';
	l = priv->line;

	len = strlen(type);
	if (strncmp(l, type, len) != 0)
		goto err;
	l += len;

	if (*l != '|')
		goto err;
	l++;

	len = strlen(priv->lastid);
	if (strncmp(l, priv->lastid, len) != 0)
		goto err;
	l += len;

	if (*l != '|')
		goto err;
	return (++l);

 err:
	log_warnx("warn: table-proc: failed to parse reply");
	fatalx("table-proc: exiting");
}

/*
 * API
 */

static int
table_proc_open(struct table *table)
{
	struct table_proc_priv	*priv;
	const char		*service;
	ssize_t			 len;
	int			 services = 0;
	int			 fd;

	priv = xcalloc(1, sizeof(*priv));

	fd = fork_proc_backend("table", table->t_config, table->t_name, 1);
	if (fd == -1)
		fatalx("table-proc: exiting");
	if ((priv->fp = fdopen(fd, "r+")) == NULL)
		fatalx("table-proc: fdopen");

	fprintf(priv->fp, "config|smtpd-version|"SMTPD_VERSION"\n");
	fprintf(priv->fp, "config|protocol|"PROTOCOL_VERSION"\n");
	fprintf(priv->fp, "config|tablename|%s\n", table->t_name);
	fprintf(priv->fp, "config|ready\n");
	if (fflush(priv->fp) == EOF)
		fatalx("table-proc: fflush");

	while ((len = getline(&priv->line, &priv->linesize, priv->fp)) != -1) {
		if (priv->line[len - 1] == '\n')
			priv->line[--len] = '\0';

		if (strncmp(priv->line, "register|", 9) != 0)
			fatalx("table-proc: invalid handshake reply");

		service = priv->line + 9;
		if (!strcmp(service, "ready"))
			break;
		else if (!strcmp(service, "alias"))
			services |= K_ALIAS;
		else if (!strcmp(service, "domain"))
			services |= K_DOMAIN;
		else if (!strcmp(service, "credentials"))
			services |= K_CREDENTIALS;
		else if (!strcmp(service, "netaddr"))
			services |= K_NETADDR;
		else if (!strcmp(service, "userinfo"))
			services |= K_USERINFO;
		else if (!strcmp(service, "source"))
			services |= K_SOURCE;
		else if (!strcmp(service, "mailaddr"))
			services |= K_MAILADDR;
		else if (!strcmp(service, "addrname"))
			services |= K_ADDRNAME;
		else if (!strcmp(service, "mailaddrmap"))
			services |= K_MAILADDRMAP;
		else if (!strcmp(service, "relayhost"))
			services |= K_RELAYHOST;
		else if (!strcmp(service, "string"))
			services |= K_STRING;
		else if (!strcmp(service, "regex"))
			services |= K_REGEX;
		else
			fatalx("table-proc: unknown service %s", service);
	}

	if (ferror(priv->fp))
		fatalx("table-proc: getline");

	if (services == 0)
		fatalx("table-proc: no services registered");

	table->t_handle = priv;

	return (1);
}

static int
table_proc_update(struct table *table)
{
	const char		*r;

	table_proc_send(table, "update", -1, NULL);
	r = table_proc_recv(table, "update-result");

	if (!strcmp(r, "ok"))
		return (1);
	if (!strcmp(r, "error"))
		return (0);

	log_warnx("warn: table-proc: failed parse reply");
	fatalx("table-proc: exiting");
}

static void
table_proc_close(struct table *table)
{
	struct table_proc_priv	*priv = table->t_handle;

	if (fclose(priv->fp) == EOF)
		fatal("table-proc: fclose");
	free(priv->line);
	free(priv);

	table->t_handle = NULL;
}

static int
table_proc_lookup(struct table *table, enum table_service s, const char *k, char **dst)
{
	const char		*req = "lookup", *res = "lookup-result";
	const char		*r;

	if (dst == NULL) {
		req = "check";
		res = "check-result";
	}

	table_proc_send(table, req, s, k);
	r = table_proc_recv(table, res);

	/* common replyes */
	if (!strcmp(r, "not-found"))
		return (0);
	if (!strcmp(r, "error"))
		return (-1);

	if (dst == NULL) {
		/* check op */
		if (!strncmp(r, "found", 5))
			return (1);
		log_warnx("warn: table-proc: failed to parse reply");
		fatalx("table-proc: exiting");
	}

	/* lookup op */
	if (strncmp(r, "found|", 6) != 0) {
		log_warnx("warn: table-proc: failed to parse reply");
		fatalx("table-proc: exiting");
	}
	r += 6;
	if (*r == '\0') {
		log_warnx("warn: table-proc: empty response");
		fatalx("table-proc: exiting");
	}
	if ((*dst = strdup(r)) == NULL)
		return (-1);
	return (1);
}

static int
table_proc_fetch(struct table *table, enum table_service s, char **dst)
{
	const char		*r;

	table_proc_send(table, "fetch", s, NULL);
	r = table_proc_recv(table, "fetch-result");

	if (!strcmp(r, "not-found"))
		return (0);
	if (!strcmp(r, "error"))
		return (-1);

	if (strncmp(r, "found|", 6) != 0) {
		log_warnx("warn: table-proc: failed to parse reply");
		fatalx("table-proc: exiting");
	}
	r += 6;
	if (*r == '\0') {
		log_warnx("warn: table-proc: empty response");
		fatalx("table-proc: exiting");
	}

	if ((*dst = strdup(r)) == NULL)
		return (-1);
	return (1);
}

struct table_backend table_backend_proc = {
	"proc",
	K_ANY,
	NULL,
	NULL,
	NULL,
	table_proc_open,
	table_proc_update,
	table_proc_close,
	table_proc_lookup,
	table_proc_fetch,
};

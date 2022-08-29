
/*
Copyright 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	"config.h"

#include	"record.h"

#include	<stdbool.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<time.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>

FILE *fout;

void
record_start(char *fname)
{
    fout = fopen(fname, "w");

    fprintf(fout,
	    "@base <http://example.org/> .\n"
	    "@prefix b:  <http://example.org/build-recorder#> .\n"
	    "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n"
	    "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n");
}

static void
record_triple(char *s, const char *p, char *o, bool o_as_string)
{
    if (o_as_string)
	fprintf(fout, "%s\t%s\t\"%s\" .\n", s, p, o);
    else
	fprintf(fout, "%s\t%s\t%s .\n", s, p, o);
}

static void
timestamp_now(char *s, size_t sz)
{
    time_t now;

    time(&now);
    strftime(s, sz, "%FT%TZ", gmtime(&now));
}

static char *
get_cmdline(pid_t pid)
{
    char cmd_fname[32];

    sprintf(cmd_fname, "/proc/%ld/cmdline", (long) pid);

    int fd = open(cmd_fname, O_RDONLY);

    if (fd < 0) {
	return NULL;
    }
#define	CMD_LINE_SIZE	1023
    char data[CMD_LINE_SIZE + 1];
    ssize_t n = read(fd, data, CMD_LINE_SIZE);

    if (n < 0) {
	return NULL;
    }

    ssize_t sz;
    bool has_spaces;
    int i;
    char *c, *w;

    sz = n;
    has_spaces = false;
    for (i = 0, c = data; i < n; i++, c++) {
	if (*c == ' ') {
	    has_spaces = true;
	} else if (*c == '\0') {
	    if (has_spaces)
		sz += 2;
	    has_spaces = false;
	}
    }

    char *ret = malloc(sz);

    if (ret == NULL) {
	return NULL;
    }

    for (i = 0, w = c = data; i < n; i++, c++) {
	if (*c == ' ') {
	    has_spaces = true;
	} else if (*c == '\0') {
	    if (has_spaces) {
		strcat(ret, "'");
		strcat(ret, w);
		strcat(ret, "'");
	    } else {
		strcat(ret, w);
	    }
	    if (i < n - 1)
		strcat(ret, " ");
	    w = c + 1;
	    has_spaces = false;
	}
    }

    return ret;
}

void
record_process_start(pid_t pid)
{
    char pbuf[32];
    char tbuf[32];
    char *cmd_line = get_cmdline(pid);

    sprintf(pbuf, "pid%ld", (long) pid);
    timestamp_now(tbuf, 32);

    record_triple(pbuf, "a", "b:process", false);
    record_triple(pbuf, "b:cmd", cmd_line, true);
    record_triple(pbuf, "b:start", tbuf, true);
}

void
record_process_end(pid_t pid)
{
    char pbuf[32];
    char tbuf[32];

    sprintf(pbuf, "pid%ld", (long) pid);
    timestamp_now(tbuf, 32);

    record_triple(pbuf, "b:end", tbuf, true);
}

void
record_process_env(pid_t pid, char **envp)
{
    char pbuf[32];

    sprintf(pbuf, "pid%ld", (long) pid);

    for (char **ep = envp; *ep != NULL; ep++)
	record_triple(pbuf, "b:env", *ep, true);
}

void
record_fileuse(char *poutname, char *foutname, char *path, int purpose,
	       char *hash)
{
    record_triple(foutname, "a", "file", false);
    record_triple(foutname, "b:name", path, true);
    record_triple(foutname, "b:hash", hash, true);

    if (purpose & O_RDONLY) {
	record_triple(poutname, "b:reads", foutname, false);
    } else if (purpose & O_WRONLY) {
	record_triple(poutname, "b:writes", foutname, false);
    } else {			       // O_RDWR
	record_triple(poutname, "b:reads", foutname, false);
	record_triple(poutname, "b:writes", foutname, false);
    }
}

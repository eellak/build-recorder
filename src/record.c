
/*
Copyright 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	"config.h"

#include	"types.h"
#include	"record.h"

#include	<stdio.h>
#include	<time.h>

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
record_triple(char *s, char *p, char *o)
{
    fprintf(fout, "%s\t%s\t%s .\n", s, p, o);
}

static void
timestamp_now(char *s, size_t sz)
{
    time_t now;

    time(&now);
    strftime(s, sz, "%FT%TZ", gmtime(&now));
}

void
record_process_start(pid_t pid, char *cmd_line)
{
    char pbuf[32];
    char tbuf[32];

    sprintf(pbuf, "pid%ld", (long) pid);
    timestamp_now(tbuf, 32);

    record_triple(pbuf, "a", "b:process");
    record_triple(pbuf, "b:cmd", cmd_line);
    record_triple(pbuf, "b:start", tbuf);
}

void
record_process_end(pid_t pid)
{
    char pbuf[32];
    char tbuf[32];

    sprintf(pbuf, "pid%ld", (long) pid);
    timestamp_now(tbuf, 32);

    record_triple(pbuf, "b:end", tbuf);
}

void
record_fileuse(pid_t pid, const FILE_INFO *file)
{
}

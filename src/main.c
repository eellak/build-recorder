
/*
Copyright (C) 2022 Valasiadis Fotios
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "config.h"

#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "record.h"

static char *output_file = "build-recorder.out";

void run_and_record_fnames(char **av);

void
record_cmdline(FILE *fout, char **ap)
{
    char **p;

    for (p = ap; *p != NULL; p++)
	(void) fprintf(fout, "%s ", *p);
    (void) fprintf(fout, "\n");
}

void
record_env(FILE *fout, char **ep)
{
    char **p;

    for (p = ep; *p != NULL; p++)
	(void) fprintf(fout, "%s\n", *p);
}

char **
handle_options(char **argv)
{
    if (!strcmp(*argv, "-o")) {
	output_file = *(++argv);
	++argv;
    }

    return argv;
}

int
main(int argc, char **argv, char **envp)
{
    if (argc < 2)
	error(EX_USAGE, 0, "missing command to record");

    argv = handle_options(++argv);

    record_start(output_file);

    record_env(stdout, envp);
    record_cmdline(stdout, argv);

    run_and_record_fnames(argv);

    exit(EXIT_SUCCESS);
}

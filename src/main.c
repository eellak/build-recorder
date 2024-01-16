
/*
Copyright (C) 2022 Valasiadis Fotios
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "record.h"
#include "portable_error.h"

void run_and_record_fnames(char **av, char **envp);

int
main(int argc, char **argv, char **envp)
{
    if (argc < 2)
	error(EX_USAGE, 0, "missing command to record");

    char *output_fname = "build-recorder.out";

    if (!strcmp(argv[1], "-o")) {
	output_fname = argv[2];
	argv += 3;
    } else {
	argv += 1;
    }

    record_start(output_fname);
    run_and_record_fnames(argv, envp);

    exit(EXIT_SUCCESS);
}

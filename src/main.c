
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

void run_and_record_fnames(char **av, char **envp);

#define CLI_USAGE \
"No command to output\n" \
"Usage:\n" \
"\t" PACKAGE_TARNAME " -h\n" \
"\t" PACKAGE_TARNAME " -v\n" \
"\t" PACKAGE_TARNAME " COMMAND\n" \
"\t" PACKAGE_TARNAME " -o <file-name> COMMAND\n" \
"\n" \
"Flags:\n" \
"\t-o\tOutput file name. Default: build-recorder.out\n" \
"\t-h\tPrint this help text and exit.\n" \
"\n" \
"Examples:\n\n" \
"Say we want to run the command 'gcc main.c -o main.o' and want to track " \
"the various interactions:\n\n" \
"$ build_recorder gcc main.c -o main.o\n" \
"or, if the output file needs a specific name:\n" \
"$ build_recorder -o foo.out gcc main.c -o main.o\n" \

int
main(int argc, char **argv, char **envp)
{
    if (argc < 2)
	error(EX_USAGE, 0, CLI_USAGE);

    char *output_fname = "build-recorder.out";

    if (!strcmp(argv[1], "-v")) {
	// Help Text
	printf("%s: Version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
	exit(EXIT_SUCCESS);
    } else if (!strcmp(argv[1], "-h")) {
	// Help Text
	printf(CLI_USAGE);
	exit(EXIT_SUCCESS);
    } else if (!strcmp(argv[1], "-o")) {

	// Usage like `build_recorder -o foo.out`
	if (argc < 4)
	    error(EX_USAGE, 0, CLI_USAGE);

	output_fname = argv[2];
	argv += 3;
    } else {
	argv += 1;
    }

    record_start(output_fname);
    run_and_record_fnames(argv, envp);

    exit(EXIT_SUCCESS);
}

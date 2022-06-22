
/*
	Copyright (C) 2022 Valasiadis Fotios
	SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include <stdio.h>
#include <string.h>
#include "tracer.h"
#include "algorithms.h"

static void *
my_strcopy_space(void *end, const char *src)
{
    return my_strcopy((char *) end, src, ' ');
}

static void *
my_strcopy_newline(void *end, const char *src)
{
    return my_strcopy((char *) end, src, '\n');
}

static void
bundle_string_array(char *buffer, char **arr,
		    void *(*bundler)(void *, const char *))
{
    buffer = accumulate_strings((void *) buffer, arr, bundler);
    buffer[-1] = '\0';
}

static void *
sum_strlen(void *sum, const char *str)
{
    return (void *) ((size_t) sum + strlen(str) + 1);
}

static unsigned long long
bundle_string_array_size(char **arr)
{
    return (size_t) accumulate_strings((void *) 0, arr, sum_strlen);
}

int
main(int argc, char **argv, char **envp)
{
    if (argc < 2)
    {
	fprintf(stderr, "build_recorder: no input\n");
	return 1;
    }

    unsigned long long args_size = bundle_string_array_size(argv + 1),
	    envp_size = bundle_string_array_size(envp);
    char buffer[args_size > envp_size ? args_size : envp_size];

    bundle_string_array(buffer, argv + 1, my_strcopy_space);

    printf("command: %s\n", buffer);

    printf("files used:\n");
    files vector;
    vector_file_new(&vector.files);

    get_files_used(argv, &vector);
    free_files(&vector);

    bundle_string_array(buffer, envp, my_strcopy_newline);

    printf("enviroment: %s\n", buffer);

    return 0;
}

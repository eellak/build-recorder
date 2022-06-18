/*
	Copyright (C) 2022 Valasiadis Fotios
	SPDX-License-Identifier: LGPL-2.1-or-later
*/

#pragma once
#include <sys/types.h>

typedef struct files {
    size_t size;
    size_t capacity;
    char **arr;
} files; //TODO

void
free_files(files *buffer);

void
tracee_main(char **argv);

int
tracer_main(pid_t pid, files *buffer);

int
get_files_used(char **argv, files *buffer);

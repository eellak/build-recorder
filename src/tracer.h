
/*
	Copyright (C) 2022 Valasiadis Fotios
	SPDX-License-Identifier: LGPL-2.1-or-later
*/

#pragma once
#include <sys/types.h>

typedef struct file {
    char *path;
} file;

#define vector_name vector_file
#define value_type file

#include "vector.h"

#undef vector_name
#undef value_type


typedef struct files {
    struct vector_file files;
} files; //TODO

void free_files(files * buffer);

int get_files_used(char **argv, files * buffer);

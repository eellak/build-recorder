/*
	Copyright (C) 2022-current Valasiadis Fotios

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
    USA
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
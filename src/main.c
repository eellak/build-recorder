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

#include <stdio.h>
#include <string.h>
#include "tracer.h"
#include "algorithms.h"

void *
my_strcopy_space(void *end, const char *src)
{
	return my_strcopy((char *)end, src, ' ');
}

void *
my_strcopy_newline(void *end, const char *src)
{
	return my_strcopy((char *)end, src, '\n');
}

void
bundle_string_array(char *buffer, char **arr, void *(*bundler)(void *, const char *))
{
	buffer = accumulate_strings((void *)buffer, arr, bundler);
	buffer[-1] = '\0';
}

void *
sum_strlen(void *sum, const char *str)
{
	return (void *)((size_t)sum + strlen(str) + 1);
}

unsigned long long
bundle_string_array_size(char **arr)
{
	return (size_t)accumulate_strings((void *)0, arr, sum_strlen);
}

int
main(int argc, char **argv, char **envp)
{
	if(argc < 2) {
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
	get_files_used(argv, &vector);	
	free_files(&vector);

	bundle_string_array(buffer, envp, my_strcopy_newline);
	
	printf("enviroment: %s\n", buffer);

	return 0;
}


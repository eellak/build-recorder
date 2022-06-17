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

/*
	char *strcpy(char *dest, const char *src) isn't what we need since it returns a pointer to the "dest" string.

	Instead we want ours to return a pointer to the end of "dest" string.

	Also worth noting that we provide a third parameteter which will be placed at the end of "dest" string.
*/
char *
my_strcopy(char *end, const char *src, char end_of_str)
{
	while(*src != '\0') {
		*end = *src;
		++end;
		++src;
	}

	*end = end_of_str;
	return end + 1;
}

int
bundle_string_array(char *buffer, char separator, char **arr) 
{
	for(; *arr; ++arr) {
		buffer = my_strcopy(buffer, *arr, arr[1] != NULL ? separator : '\0');
	}
	
	return 0;
}

unsigned long long
string_array_size(char **arr) 
{
	unsigned long long size = 0;
	
	for(; *arr; ++arr) {
		size += strlen(*arr) + 1;
	}

	return size;
}

int
main(int argc, char **argv, char **envp)
{
	if(argc < 2) {
		fprintf(stderr, "build_recorder: no input\n");
		return 1;
	}

	unsigned long long args_size = string_array_size(argv + 1),
		envp_size = string_array_size(envp);
	char buffer[args_size > envp_size ? args_size : envp_size];

	if(bundle_string_array(buffer, ' ', argv + 1)) {
		// TODO ERROR
	}
	printf("command: %s\n", buffer);
	
	printf("files used:\n");
	files vector;
	get_files_used(argv, &vector);	
	free_files(&vector);

	if(bundle_string_array(buffer, '\n', envp)) {
		// TODO ERROR
	}
	printf("enviroment: %s\n", buffer);

	return 0;
}


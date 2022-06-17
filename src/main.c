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

int
bundle_string_array(char *buffer, char separator, char **arr) {
	int i = 0;
	unsigned long long end = 0;
	while(arr[i]) {
		unsigned long long index = 0;
		while(arr[i][index] != '\0') {
			buffer[end] = arr[i][index];
			++end;
			++index;
		}
		++i;
		buffer[end] = arr[i] != NULL ? separator : '\0';
		++end;
	}
	
	return 0;
}

unsigned long long
string_array_size(char **arr) {
	int i = 0;
	unsigned long long size = 0;
	
	while(arr[i]) {
		size += strlen(arr[i]) + 1;
		++i;
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


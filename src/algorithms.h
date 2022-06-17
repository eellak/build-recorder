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


void *
accumulate_strings(void *n, char **arr, void *(*op)(void *e, const char *str));

/*
	char *strcpy(char *dest, const char *src) isn't what we need since it returns a pointer to the "dest" string.

	Instead we want ours to return a pointer to the end of "dest" string.

	Also worth noting that we provide a third parameteter which will be placed at the end of "dest" string.
*/
char *
my_strcopy(char *end, const char *src, char end_of_str);
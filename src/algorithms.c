/*
	Copyright (C) 2022 Valasiadis Fotios
	SPDX-License-Identifier: LGPL-2.1-or-later
*/


void *
accumulate_strings(void *n, char **arr, void *(*op)(void *e, const char *str))
{
	while(*arr) {
		n = op(n, *arr);
		++arr;
	}

	return n;
}

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

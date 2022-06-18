
/*
	Copyright (C) 2022 Valasiadis Fotios
	SPDX-License-Identifier: LGPL-2.1-or-later
*/

#pragma once

void *accumulate_strings(void *n, char **arr,
			 void *(*op)(void *e, const char *str));

/*
	char *strcpy(char *dest, const char *src) isn't what we need since it returns a pointer to the "dest" string.

	Instead we want ours to return a pointer to the end of "dest" string.

	Also worth noting that we provide a third parameteter which will be placed at the end of "dest" string.
*/
char *my_strcopy(char *end, const char *src, char end_of_str);

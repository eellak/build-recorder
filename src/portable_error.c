/*
Copyright (C) 2022 Fotios Valasiadis
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	"config.h"

#ifndef HAVE_ERROR_H

#include 	<stdio.h>
#include 	<stdlib.h>
#include	<stdarg.h>
#include	<string.h>

void
error(int status, int errnum, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    vfprintf(stderr, format, args);

    if (errnum != 0) {
	fprintf(stderr, ": %s", strerror(errnum));
    }

    fprintf(stderr, "\n");

    va_end(args);

    if (status != 0) {
	exit(status);
    }
}

#endif

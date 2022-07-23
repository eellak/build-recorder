
/*
 * test program to read include files specified in the command-line
 *
 * Copyright (C) 2022 Alexios Zavras
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define	MAX_TIME_FILE_OPEN	10     // seconds

void
read_file(char *fpath)
{
    int             fd = open(fpath, O_RDONLY);

    (void) printf("[%jd] opened(%s)= %d\n", (intmax_t) getpid(), fpath, fd);

    unsigned int    secs = random() % MAX_TIME_FILE_OPEN;

    sleep(secs);

    close(fd);
    (void) printf("[%jd] closed(%d)\n", (intmax_t) getpid(), fd);

    return;
}

char           *dirpaths[] =
	{ ".", "/usr/local/include", "/usr/include", "/usr/include/sys", NULL };

void
setup_dirpaths(void)
{
    char           *cpp_flags = getenv("CPPFLAGS");

    // TODO: set up the global variable according to environent
    return;
}

void
open_incl_file(char *fn)
{
    if (*fn == '/') {		       // absolute path
	read_file(fn);
    } else {
	char            buf[PATH_MAX];

	for (char **d = dirpaths; *d; d++) {
	    sprintf(buf, "%s/%s", *d, fn);
	    if (access(buf, R_OK) == 0) {
		read_file(buf);
		return;
	    }
	}
    }
}

int
main(int argc, char **argv)
{
    for (char **s = ++argv; *s; s++)
	open_incl_file(*s);
}

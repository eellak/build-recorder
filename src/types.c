
/*
Copyright (C) 2022 Valasiadis Fotios
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	<stdio.h>	       /* sprintf(3) */
#include	<stdlib.h>	       /* calloc(3), reallocarray(3) */
#include	<string.h>	       /* strcmp(3) */
#include	<error.h>	       /* error(3) */
#include	<errno.h>	       /* errno */

#include	"types.h"

/* PROCESS_INFO methods */

void
pinfo_new(PROCESS_INFO *self, int numpinfo, pid_t pid, char ignore_one_sigstop)
{
    sprintf(self->outname, ":p%d", numpinfo);
    self->pid = pid;
    self->finfo_size = DEFAULT_FINFO_SIZE;
    self->finfo = calloc(self->finfo_size, sizeof (FILE_INFO));
    self->ignore_one_sigstop = ignore_one_sigstop;
}

int *
pinfo_finfo_at(PROCESS_INFO *self, int index)
{
    if (index >= self->finfo_size) {
	int prev_size = self->finfo_size;

	do {
	    self->finfo_size *= 2;
	} while (index >= self->finfo_size);

	self->finfo =
		reallocarray(self->finfo, self->finfo_size, sizeof (FILE_INFO));
	if (self->finfo == NULL) {
	    error(EXIT_FAILURE, errno,
		  "reallocating file info array in process %d", self->pid);
	}

	for (int i = prev_size; i < self->finfo_size; ++i) {
	    self->finfo[i] = -1;
	}
    }

    return self->finfo + index;
}

/* FILE_INFO methods */

void
finfo_new(FILE_INFO *self, int numfinfo, char *path, char *abspath, char *hash)
{
    sprintf(self->outname, ":f%d", numfinfo);
    self->was_hash_printed = 0;
    self->path = path;
    self->abspath = abspath;
    self->hash = hash;
}

/* CONTEXT methods */

void
context_init(CONTEXT *self)
{
    self->finfo_size = DEFAULT_FINFO_SIZE;
    self->finfo = calloc(self->finfo_size, sizeof (FILE_INFO));
    self->numfinfo = -1;

    self->pinfo_size = DEFAULT_PINFO_SIZE;
    self->pinfo = calloc(self->pinfo_size, sizeof (PROCESS_INFO));
    self->numpinfo = -1;
}

FILE_INFO *
context_next_finfo(CONTEXT *self)
{
    if (self->numfinfo == self->finfo_size - 1) {
	self->finfo_size *= 2;
	self->finfo =
		reallocarray(self->finfo, self->finfo_size, sizeof (FILE_INFO));
	if (self->finfo == NULL)
	    error(EXIT_FAILURE, errno, "reallocating file info array");
    }

    return self->finfo + (++self->numfinfo);
}

FILE_INFO *
context_find_finfo(const CONTEXT *self, char *abspath, char *hash)
{
    int i = self->numfinfo;

    while (i >= 0 && !(!strcmp(abspath, self->finfo[i].abspath)
		       && (!(self->finfo[i].was_hash_printed)
			   || (hash == NULL && self->finfo[i].hash == NULL)
			   || !strcmp(hash, self->finfo[i].hash)))) {
	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return self->finfo + i;
}

PROCESS_INFO *
context_next_pinfo(CONTEXT *self)
{
    if (self->numpinfo == self->pinfo_size - 1) {
	self->pinfo_size *= 2;
	self->pinfo =
		reallocarray(self->pinfo, self->pinfo_size,
			     sizeof (PROCESS_INFO));
	if (self->pinfo == NULL)
	    error(EXIT_FAILURE, errno, "reallocating process info array");
    }

    return self->pinfo + (++self->numpinfo);
}

PROCESS_INFO *
context_find_pinfo(const CONTEXT *self, pid_t pid)
{
    int i = self->numpinfo;

    while (i >= 0 && self->pinfo[i].pid != pid) {
	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return self->pinfo + i;
}

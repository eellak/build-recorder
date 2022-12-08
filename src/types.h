
/*
Copyright (C) 2022 Alexios Zavras
Copyright (C) 2022 Valasiadis Fotios
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include        <linux/ptrace.h>

/*
 * For each file, we keep its name/path
 * (the argument to the open(2) call that opened it,
 * whether it was opened for reading or for writing
 * (re-using the O_ flags),
 * and a hash of the contents.
 * Not all info is added at the same time.
 */
typedef struct {
    char was_hash_printed;
    char *path;
    char *abspath;
    char *hash;
    char outname[16];
} FILE_INFO;

/*
 * For each (sub-)process we keep its pid,
 * the command line (including all the arguments)
 * the number of files recorded,
 * the actual information on the files,
 * and, while it's running, its current syscall
 * stop info struct.
 */
typedef struct {
    char outname[16];
    pid_t pid;
    char *cmd_line;
    int *finfo;
    int finfo_size;
    struct ptrace_syscall_info state;
    void *entry_info;
    char ignore_one_sigstop;
} PROCESS_INFO;

typedef struct {
    FILE_INFO *finfo;
    int numfinfo;
    int finfo_size;
} FINFOS;

typedef struct {
    PROCESS_INFO *pinfo;
    int numpinfo;
    int pinfo_size;
} PINFOS;

/* PROCESS_INFO methods */
void pinfo_new(PROCESS_INFO *self, int numpinfo, pid_t pid,
	       char ignore_one_sigstop);
int *pinfo_finfo_at(PROCESS_INFO *self, int index);

/* FILE_INFO methods */
void finfo_new(FILE_INFO *self, int numfinfo, char *path, char *abspath,
	       char *hash);

/* FINFOS methods */
#define DEFAULT_FINFO_SIZE	32

void finfos_init(FINFOS *self);
FILE_INFO *finfos_next_finfo(FINFOS *self);
FILE_INFO *finfos_find_finfo(FINFOS *self, char *abspath, char *hash);

/* PINFOS methods */
#define DEFAULT_PINFO_SIZE	32

void pinfos_init(PINFOS *self);
PROCESS_INFO *pinfos_next_pinfo(PINFOS *self);
PROCESS_INFO *pinfos_find_pinfo(PINFOS *self, pid_t pid);

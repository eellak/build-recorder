
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
#include <stdint.h>

#include <sys/ptrace.h>

/*
 * For each file, we keep its name/path
 * (the argument to the open(2) call that opened it,
 * whether it was opened for reading or for writing
 * (re-using the O_ flags),
 * and a hash of the contents.
 * Not all info is added at the same time.
 */
typedef struct {
    char *path;
    char *abspath;
    char *hash;
    size_t size;
    char outname[16];
} FILE_INFO;

/*
 * For each (sub-)process we keep its pid,
 * the command line (including all the arguments)
 * the list of files that are currently open for writing,
 * and, while it's running, its current syscall number
 * and arguments.
 */
typedef struct {
    char outname[16];
    char *cmd_line;
    int *fds;
    FILE_INFO *finfo;
    int numfinfo;
    int finfo_size;
    uint64_t nr;
    uint64_t args[6];
    void *entry_info;
    char ignore_one_sigstop;
} PROCESS_INFO;


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
 * For each file, we keep its absolute path
 * and a hash of the contents.
 */
typedef struct {
    char *abspath;
    char *hash;
    char outname[16];
} FILE_INFO;

/*
 * For each (sub-)process we keep its pid,
 * the command line (including all the arguments)
 * the list of files that are currently open for writing,
 * and, while it's running, its current syscall
 * stop info struct.
 */
typedef struct {
    char outname[16];
    char *cmd_line;
    int *fds;
    FILE_INFO *finfo;
    int numfinfo;
    int finfo_size;
    struct ptrace_syscall_info state;
    void *entry_info;
    char ignore_one_sigstop;
} PROCESS_INFO;

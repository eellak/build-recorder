
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
    int purpose;
    uint8_t *hash;
} FILE_INFO;

/*
 * For each (sub-)process we keep its pid,
 * the command line (including all the arguments)
 * the number of files recorded,
 * the actual information on the files,
 * and, while it's running,
 * a map of open descriptors to file infomation entries,
 * and its current syscall stop info struct.
 */
typedef struct {
    pid_t pid;
    char *cmd_line;
    int numfinfo;
    FILE_INFO *finfo;
    int finfo_size;
    int open_files[1024];
    struct ptrace_syscall_info state;
} PROCESS_INFO;

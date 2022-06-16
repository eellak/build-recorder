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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
#include "tracer.h"

#define FATAL_ERROR \
	fprintf(stderr, "error: %s\n", strerror(errno)); \
	_exit(1)

void
tracee_main(char **argv)
{
	ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
	execvp(*argv, argv);
	FATAL_ERROR; // exec shouldn't return.
}

/*
    Checks for \0 at last *size* bytes.
*/
int
has_end_of_str(char *buffer, size_t size)
{
    for(size_t i = 0; i < size; ++i) {
        if(buffer[i] == '\0') {
            return 1;
        }
    }

    return 0;
}

#define MAXPATHLEN 10240 / sizeof(long)

/*
    addr is an address pointing to the tracee process' address space, thus we need to copy it.
*/
char *
read_str_from_process(char *addr, pid_t pid)
{
    static long buffer[MAXPATHLEN];
    size_t size = 0;
    
    do {
        buffer[size] = ptrace(PTRACE_PEEKDATA, pid, addr + size * sizeof(long), NULL);
    } while(!has_end_of_str((char *)(buffer + size), sizeof(long)) && ++size != MAXPATHLEN);

    if(size == MAXPATHLEN) {
        fprintf(stderr, "maximum file path size of %ld exceeded", MAXPATHLEN);
        _exit(1);
    }

    return (char *)buffer;
}

void
handle_syscall(pid_t pid, const struct ptrace_syscall_info *entry, const struct ptrace_syscall_info *exit, files *buffer)
{
    if(exit->exit.rval < 0) {
        return; // return on syscall failure
    }

    int syscall = entry->entry.nr;

    if(syscall == SYS_open || syscall == SYS_creat) {
        puts(read_str_from_process((char *)entry->entry.args[0], pid));
    } else if(syscall == SYS_openat) {
        puts(read_str_from_process((char *)entry->entry.args[1], pid));
    }
}

int
tracer_main(pid_t pid, files *buffer)
{
	waitpid(pid, NULL, 0);
	ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

	struct ptrace_syscall_info entry;
    struct ptrace_syscall_info exit;
	while(1) {
		if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
			FATAL_ERROR;
		}
		if(waitpid(pid, NULL, 0) < 0) {
			FATAL_ERROR;
		}

		if(ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(entry), &entry) == -1) {
			FATAL_ERROR;
		}

		if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
			FATAL_ERROR;
		}
		if(waitpid(pid, NULL, 0) < 0) {
			FATAL_ERROR;
		}

		if(ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(exit), &exit) == -1) {
			if(errno == ESRCH) {
				return exit.exit.rval;
			}
			FATAL_ERROR;
		}

        handle_syscall(pid, &entry, &exit, buffer);
	}
}

int
get_files_used(char **argv, files *buffer)
{
	pid_t pid;

	switch(pid = fork()) {
		case -1:
			FATAL_ERROR;
		case 0:
			tracee_main(argv + 1);
	}
	
	return tracer_main(pid, buffer);
}

void
free_files(files *buffer)
{
    //TODO
}
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

int
is_open_syscall(int syscall)
{
#define is(what) syscall == SYS_##what
	return is(open) || is(openat) || is(creat);
#undef is
}

void
tracer_main(pid_t pid, int argc, char **argv)
{
	waitpid(pid, NULL, 0);
	ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

	struct ptrace_syscall_info info;
	while(1) {
		if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
			FATAL_ERROR;
		}
		if(waitpid(pid, NULL, 0) < 0) {
			FATAL_ERROR;
		}

		if(ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(info), &info) == -1) {
			FATAL_ERROR;
		}

		if(is_open_syscall(info.entry.nr)) {
			printf("%lld\n", info.entry.nr);
		}

		if(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
			FATAL_ERROR;
		}
		if(waitpid(pid, NULL, 0) < 0) {
			FATAL_ERROR;
		}

		if(ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *)sizeof(info), &info) == -1) {
			if(errno == ESRCH) {
                // TODO report tracee's return value "info.exit.rval"
				break;
			}
			FATAL_ERROR;
		}
	}
}

int
get_files_used(int argc, char **argv, char **envp, files *buffer)
{
	pid_t pid;

	switch(pid = fork()) {
		case -1:
			FATAL_ERROR;
		case 0:
			tracee_main(argv + 1);
	}
	
	tracer_main(pid, argc, argv);
}

void
free_files(files *buffer)
{
    //TODO
}
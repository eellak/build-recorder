
/*
	Copyright (C) 2022 Valasiadis Fotios
	SPDX-License-Identifier: LGPL-2.1-or-later
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

static void
tracee_main(char **argv)
{
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
    execvp(*argv, argv);
    FATAL_ERROR;		       // exec shouldn't return.
}

/*
    Checks for \0 at last *size* bytes.
*/
static int
has_end_of_str(const char *buffer, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
	if (buffer[i] == '\0')
	{
	    return 1;
	}
    }

    return 0;
}

#define vector_name vector_long
#define value_type long

#include "vector.h"

#undef vector_name
#undef value_type

/*
    addr is an address pointing to the tracee process' address space, thus we need to copy it.
*/
static const char *
read_str_from_process(char *addr, pid_t pid)
{
    struct vector_long buffer;
    const char *cbuffer = (char *) buffer.arr;	// For readability
    
    do
    {
	long bytes =
		ptrace(PTRACE_PEEKDATA, pid, addr + buffer.size * sizeof (long), NULL);
	vector_long_push_back(&buffer, &bytes);
    } while (!has_end_of_str(cbuffer + buffer.size * sizeof (long), sizeof (long)));

    return cbuffer;
}

static void
handle_syscall(pid_t pid, const struct ptrace_syscall_info *entry,
	       const struct ptrace_syscall_info *exit, files *buffer)
{
    if (exit->exit.rval < 0)
    {
	return;			       // return on syscall failure
    }

    int syscall = entry->entry.nr;
    file f;

    if (syscall == SYS_open || syscall == SYS_creat)
    {
	f.path = read_str_from_process((char *) entry->entry.args[0], pid);
    } else if (syscall == SYS_openat)
    {
	f.path = read_str_from_process((char *) entry->entry.args[1], pid);
    }

    vector_file_push_back(buffer->files, &f);
}

static int
tracer_main(pid_t pid, files *buffer)
{
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_SETOPTIONS, pid, NULL,
	   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

    struct ptrace_syscall_info entry;
    struct ptrace_syscall_info exit;

    while (1)
    {
	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
	{
	    FATAL_ERROR;
	}
	if (waitpid(pid, NULL, 0) < 0)
	{
	    FATAL_ERROR;
	}

	if (ptrace
	    (PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof (entry),
	     &entry) == -1)
	{
	    FATAL_ERROR;
	}

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
	{
	    FATAL_ERROR;
	}
	if (waitpid(pid, NULL, 0) < 0)
	{
	    FATAL_ERROR;
	}

	if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof (exit), &exit)
	    == -1)
	{
	    if (errno == ESRCH)
	    {
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

    switch (pid = fork())
    {
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
    // TODO
}

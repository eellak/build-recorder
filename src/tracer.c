
/*
	Copyright (C) 2022 Valasiadis Fotios
	SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
#include <sys/signal.h>
#include "tracer.h"

#define FATAL_ERROR \
	fprintf(stderr, "error: %s\n", strerror(errno)); \
	_exit(1)

#define FATAL_ERROR_MSG(...) \
	fprintf(stderr, __VA_ARGS__); \
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

#define MAXPATHLEN 10240 / sizeof(long)

/*
    addr is an address pointing to the tracee process' address space, thus we need to copy it.
*/
static const char *
read_str_from_process(char *addr, pid_t pid)
{
    static long buffer[MAXPATHLEN];
    static const char *cbuffer = (char *) buffer;	// For readability
    size_t size = 0;

    do
    {
	buffer[size] =
		ptrace(PTRACE_PEEKDATA, pid, addr + size * sizeof (long), NULL);
    } while (!has_end_of_str(cbuffer + size, sizeof (long)) &&
	     ++size != MAXPATHLEN);

    if (size == MAXPATHLEN && cbuffer[size * sizeof (long) - 1] != '\0')
    {
	FATAL_ERROR_MSG("maximum file path size of %ld exceeded", MAXPATHLEN);
    }

    return cbuffer;
}

static void
handle_syscall(pid_t pid, const struct ptrace_syscall_info *entry,
	       const struct ptrace_syscall_info *exit, files * buffer)
{
    if (exit->exit.rval < 0)
    {
	return;			       // return on syscall failure
    }

    int syscall = entry->entry.nr;

    if (syscall == SYS_open || syscall == SYS_creat)
    {
	puts(read_str_from_process((char *) entry->entry.args[0], pid));
    } else if (syscall == SYS_openat)
    {
	puts(read_str_from_process((char *) entry->entry.args[1], pid));
    }
}

static int
tracer_main(pid_t pid, files * buffer)
{
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_SETOPTIONS, pid, NULL,	// Options are inherited
	   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    struct ptrace_syscall_info entry;
    struct ptrace_syscall_info exit;

    size_t running = 1;		  // Running threads
    int signal;
    int rval;
    pid_t tracee_pid = pid;

    while (running)
    {
	if (pid >= 0 && ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
	{
	    FATAL_ERROR;
	}

	pid = wait(&signal);	       // Wait for any child
	if (pid < 0)
	{
	    FATAL_ERROR;
	}

	if (!WIFSTOPPED(signal) || WSTOPSIG(signal) != (SIGTRAP | 0x80))
	{
	    FATAL_ERROR_MSG("expecting syscall stop\n");
	}

	if (ptrace
	    (PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof (entry),
	     &entry) == -1)
	{
	    FATAL_ERROR;
	}

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0 ||
	    waitpid(pid, &signal, 0) < 0)
	{
	    FATAL_ERROR;
	}

	if (WIFSTOPPED(signal))
	{
	    signal = WSTOPSIG(signal);
	} else if (WIFEXITED(signal))
	{
	    if (pid == tracee_pid)
	    {
		rval = WEXITSTATUS(signal);
	    }
	    --running;
	    pid = -1;		       // Shouldn't send a syscall signal to
				       // a dead process
	    continue;
	} else
	{
	    FATAL_ERROR_MSG
		    ("expecting syscall stop, event stop, or tracee death\n");
	}

	// printf("exit signal:%d\n", signal);

	if (signal == SIGTRAP)
	{
	    ++running;
	    pid_t parent = pid;

	    if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &pid) < 0 ||
		waitpid(pid, &signal, 0) < 0)
	    {
		FATAL_ERROR;
	    }

	    if (!WIFSTOPPED(signal) || WSTOPSIG(signal) != SIGSTOP)
	    {
		FATAL_ERROR_MSG("signal should be SIGSTOP\n");
	    }
	    // Reading and ignoring clone/fork/vfork syscall exit
	    if (ptrace(PTRACE_SYSCALL, parent, NULL, NULL) < 0 ||
		waitpid(parent, NULL, 0) < 0)
	    {
		FATAL_ERROR;
	    }
	    // Restarting parent
	    if (ptrace(PTRACE_SYSCALL, parent, NULL, NULL) < 0)
	    {
		FATAL_ERROR;
	    }

	    continue;		       // Child will be signaled to continue
				       // upon next iteration
	}

	if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof (exit), &exit)
	    < 0)
	{
	    FATAL_ERROR;
	}

	handle_syscall(pid, &entry, &exit, buffer);
    }

    return rval;
}

int
get_files_used(char **argv, files * buffer)
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
free_files(files * buffer)
{
    // TODO
}

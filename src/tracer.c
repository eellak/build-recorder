
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

#define vector_name vector_long
#define value_type long

#include "vector.h"

#undef vector_name
#undef value_type

/*
    addr is an address pointing to the tracee process' address space, thus we need to copy it.
*/
static char *
read_str_from_process(char *addr, pid_t pid)
{
    struct vector_long buffer;
    vector_long_new(&buffer);
    vector_long_reserve(&buffer, 16 / sizeof(long));
    
    do
    {
	long bytes =
		ptrace(PTRACE_PEEKDATA, pid, addr + buffer.size * sizeof (long), NULL);
	vector_long_push_back(&buffer, &bytes);
    } while (!has_end_of_str((char *) (buffer.arr + buffer.size - 1), sizeof (long)));

    return (char *) buffer.arr;
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

    vector_file_push_back(&buffer->files, &f);
}

typedef struct state
{
    struct ptrace_syscall_info info;
    pid_t pid;
} state;

#define vector_name vector_state
#define value_type state

#include "vector.h"

#undef vector_name
#undef value_type

state *
find(const struct vector_state *vec, pid_t pid)
{
    for (size_t i = 0; i < vec->size; ++i)
    {
	if (vec->arr[i].pid == pid)
	{
	    return vec->arr + i;
	}
    }

    FATAL_ERROR_MSG("process %d isn't in children\n", pid);
}

static int
tracer_main(pid_t pid, files *buffer)
{
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_SETOPTIONS, pid, NULL,	// Options are inherited
	   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    struct ptrace_syscall_info info;
    struct vector_state children;

    vector_state_new(&children);
    vector_state_reserve(&children, 16);

    state temp;

    temp.pid = pid;
    vector_state_push_back(&children, &temp);

    int status;
    int rval;
    pid_t tracee_pid = pid;
    state *process_state;

    // Starting tracee
    if (ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL) < 0)
    {
	FATAL_ERROR;
    }

    while (children.size)
    {
	pid = wait(&status);

	if (pid < 0)
	{
	    FATAL_ERROR;
	}

	if (WIFSTOPPED(status))
	{
	    switch (WSTOPSIG(status))
	    {
		case SIGTRAP | 0x80:
		    process_state = find(&children, pid);

		    if (ptrace
			(PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof (info),
			 &info) < 0)
		    {
			FATAL_ERROR;
		    }

		    switch (info.op)
		    {
			case PTRACE_SYSCALL_INFO_ENTRY:
			    process_state->info = info;
			    break;
			case PTRACE_SYSCALL_INFO_EXIT:
			    handle_syscall(pid, &process_state->info, &info,
					   buffer);
			    break;
			default:
			    FATAL_ERROR_MSG
				    ("expected PTRACE_SYSCALL_INFO_ENTRY or PTRACE_SYSCALL_INFO_EXIT\n");
		    }

		    break;
		case SIGTRAP:	       // Caused from fork/vfork/clone/.
				       // Ignored, the child will be handled
				       // at SYGSTOP instead.
		    // Reading and ignoring clone/fork/vfork syscall exit
		    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0 ||
			waitpid(pid, NULL, 0) < 0)
		    {
			FATAL_ERROR;
		    }

		    break;
		case SIGSTOP:
		    temp.pid = pid;
		    vector_state_push_back(&children, &temp);
		    break;
		default:
		    FATAL_ERROR_MSG("unexpected signal\n");
	    }

	    // Restarting process 
	    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0)
	    {
		FATAL_ERROR;
	    }
	} else if (WIFEXITED(status))  // child process exited
	{
	    *find(&children, pid) = children.arr[children.size - 1];
	    --children.size;

	    if (pid == tracee_pid)
	    {
		rval = WEXITSTATUS(status);
	    }
	} else
	{
	    FATAL_ERROR_MSG("expected stop or tracee death\n");
	}
    }

    return rval;
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

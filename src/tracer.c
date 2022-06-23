
/*
Copyright (C) 2022 Valasiadis Fotios
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	"config.h"

#include	<errno.h>
#include	<error.h>
#include	<limits.h>
#include	<stdint.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>

#include	<sys/ptrace.h>

#include	"types.h"

//      #include <sys/syscall.h>
//      #include <sys/wait.h>
//      #include <linux/ptrace.h>
//      #include <sys/signal.h>

/*
 * variables for the list of processes,
 * its size and the array size
 */

PROCESS_INFO *pinfo;
int numpinfo;
int pinfo_size;

#define	DEFAULT_PINFO_SIZE	32
#define	DEFAULT_FINFO_SIZE	32

/*
 * memory allocators for pinfo
 */

void
init_pinfo(void)
{
    pinfo_size = DEFAULT_PINFO_SIZE;
    pinfo = calloc(pinfo_size, sizeof (PROCESS_INFO));
    numpinfo = -1;
}

PROCESS_INFO *
next_pinfo(void)
{
    if (numpinfo < pinfo_size)
	return &(pinfo[++numpinfo]);

    pinfo_size *= 2;
    pinfo = reallocarray(pinfo, pinfo_size, sizeof (PROCESS_INFO));
    if (pinfo == NULL)
	error(EXIT_FAILURE, errno, "reallocating process info array");
    return &(pinfo[++numpinfo]);
}

FILE_INFO *
next_finfo(PROCESS_INFO *pi)
{
    if (pi->numfinfo < pi->finfo_size)
	return &(pi->finfo[++(pi->numfinfo)]);

    pi->finfo_size *= 2;
    pi->finfo = reallocarray(pi->finfo, pi->finfo_size, sizeof (FILE_INFO));
    if (pi->finfo == NULL)
	error(EXIT_FAILURE, errno, "reallocating file info array in process %d",
	      pi->pid);
    return &(pi->finfo[++(pi->numfinfo)]);
}

char *
get_str_from_process(pid_t pid, void *addr)
{
    static char buf[PATH_MAX];
    char *dest = buf;
    union
    {
	long lval;
	char cval[sizeof (long)];
    } data;

    for (int i = 0;; i++)
    {
	data.lval =
		ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof (long), NULL);
	for (int j = 0; j < sizeof (long); j++)
	{
	    *dest++ = data.cval[j];
	    if (data.cval[j] == 0)
		break;
	}
    }
    return strdup(buf);
}

/*====================================================================================*/

#if 0
// still TODO

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

typedef struct state
{
    struct ptrace_syscall_info info;
    pid_t pid;
} state;

#  define vector_name vector_state
#  define value_type state

#  include "vector.h"

#  undef vector_name
#  undef value_type

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
tracer_main(pid_t pid, files * buffer)
{
    printf("%d entered\n", pid);
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

#endif

/*====================================================================================*/

void
trace(pid_t pid)
{
    PROCESS_INFO *pi;

    pi = next_pinfo();
    pi->pid = pid;

    pi->finfo_size = DEFAULT_FINFO_SIZE;
    pi->finfo = calloc(pi->finfo_size, sizeof (FILE_INFO));
    pi->numfinfo = -1;
}

void
run_tracee(char **av)
{
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
    execvp(*av, av);
    error(EXIT_FAILURE, errno, "after child exec()");
}

void
run_and_record_fnames(char **av)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
	error(EXIT_FAILURE, errno, "in original fork()");
    else if (pid == 0)
	run_tracee(av);

    init_pinfo();
    trace(pid);

}

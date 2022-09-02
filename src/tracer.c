
/*
Copyright (C) 2022 Valasiadis Fotios
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	"config.h"

#include	<errno.h>
#include	<error.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>

#include	<sys/ptrace.h>
#include	<linux/ptrace.h>

#include	<sys/signal.h>
#include	<sys/syscall.h>
#include	<sys/wait.h>
#include	<linux/limits.h>

#include	"types.h"
#include	"hash.h"
#include	"record.h"

/*
 * variables for the list of processes,
 * its size and the array size
 */

PROCESS_INFO *pinfo;
int numpinfo;
int pinfo_size;

int numfinfo = 0;

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

    PROCESS_INFO *next = pinfo + (++numpinfo);

    sprintf(next->outname, "p%d", numpinfo);
    return next;
}

FILE_INFO *
finfo_at(PROCESS_INFO *pi, int index)
{
    if (index >= pinfo->finfo_size) {
	int prev_size = pinfo->finfo_size;

	do {
	    pinfo->finfo_size *= 2;
	} while (index >= pinfo->finfo_size);

	pi->finfo = reallocarray(pi->finfo, pi->finfo_size, sizeof (FILE_INFO));
	if (pi->finfo == NULL) {
	    error(EXIT_FAILURE, errno,
		  "reallocating file info array in process %d", pi->pid);
	}

	FILE_INFO *base = pi->finfo + prev_size;
	int size = pi->finfo_size - prev_size;

	for (int i = 0; i < size; ++i) {
	    base[i].purpose = 0;
	}
    }

    return pinfo->finfo + index;
}

PROCESS_INFO *
find(pid_t pid)
{
    size_t i = numpinfo;

    while (i >= 0 && pinfo[i].pid != pid) {
	--i;
    }

    if (i < 0) {
	error(EXIT_FAILURE, errno, "process %d isn't in array\n", pid);
    }

    return pinfo + i;
}

static void
handle_open(int pid, int fd, int flags)
{
    FILE_INFO *finfo = finfo_at(find(pid), fd);

    finfo->purpose = flags;

    static char fd_link[32];

    sprintf(fd_link, "/proc/%ld/fd/%d", (long) pid, fd);

    finfo->fd = open(fd_link, O_RDONLY);

    if (finfo->fd < 0) {
	error(EXIT_FAILURE, errno, "on handle_open open");
    }

    static char path[PATH_MAX];

    int len = readlink(fd_link, path, PATH_MAX);

    if (len < 0) {
	error(EXIT_FAILURE, errno, "on handle_open readlink");
    }
    path[len] = '\0';

    finfo->path = strdup(path);
}

static void
handle_syscall(pid_t pid, const struct ptrace_syscall_info *entry,
	       const struct ptrace_syscall_info *exit)
{
    if (exit->exit.rval < 0) {
	return;			       // return on syscall failure
    }

    int fd;
    void *path;
    int flags;
    int dirfd;
    FILE_INFO *finfo;
    FILE_INFO *dir;

    switch (entry->entry.nr) {
	case SYS_open:
	    // int open(const char *pathname, int flags, ...);
	    fd = (int) exit->exit.rval;
	    flags = (int) entry->entry.args[1];

	    handle_open(pid, fd, flags);
	    break;
	case SYS_creat:
	    // int creat(const char *pathname, ...);
	    fd = (int) exit->exit.rval;
	    flags = O_CREAT | O_WRONLY | O_TRUNC;

	    handle_open(pid, fd, flags);
	    break;
	case SYS_openat:
	    // int openat(int dirfd, const char *pathname, int flags, ...);
	    fd = (int) exit->exit.rval;
	    flags = (int) entry->entry.args[2];

	    handle_open(pid, fd, flags);
	    break;
	case SYS_close:
	    // int close(int fd);
	    fd = (int) entry->entry.args[0];

	    finfo = find(pid)->finfo + fd;

	    if (finfo->purpose != 0) { // If the file has been opened.
		char *hash = get_file_hash(finfo->fd);

		close(finfo->fd);
		record_fileuse(find(pid)->outname, finfo->outname, finfo->path,
			       finfo->purpose, hash);
		finfo->purpose = 0;    // file is closed again.
		free(finfo->path);
		free(hash);
	    }
	    break;
	case SYS_execve:
	    // int execve(const char *pathname, char *const argv[],
	    // char *const envp[]);
	    record_process_start(pid);
	    break;
	case SYS_execveat:
	    // int execveat(int dirfd, const char *pathname,
	    // const char *const argv[], const char * const envp[],
	    // int flags);
	    record_process_start(pid);
	    break;
	default:
	    return;
    }
}

static void
tracer_main(pid_t pid, char **envp)
{
    waitpid(pid, NULL, 0);

    record_process_start(pid);
    record_process_env(pid, envp);

    ptrace(PTRACE_SETOPTIONS, pid, NULL,	// Options are inherited
	   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    struct ptrace_syscall_info info;
    static size_t running = 1;

    int status;
    pid_t tracee_pid = pid;
    PROCESS_INFO *process_state;

    // Starting tracee
    if (ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL) < 0) {
	error(EXIT_FAILURE, errno, "tracee PTRACE_SYSCALL failed");
    }

    while (running) {
	pid = wait(&status);

	if (pid < 0) {
	    error(EXIT_FAILURE, errno, "wait failed");
	}

	if (WIFSTOPPED(status)) {
	    switch (WSTOPSIG(status)) {
		case SIGTRAP | 0x80:
		    process_state = find(pid);

		    if (ptrace
			(PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof (info),
			 &info) < 0) {
			error(EXIT_FAILURE, errno,
			      "tracee PTRACE_GET_SYSCALL_INFO failed");
		    }

		    switch (info.op) {
			case PTRACE_SYSCALL_INFO_ENTRY:
			    process_state->state = info;
			    break;
			case PTRACE_SYSCALL_INFO_EXIT:
			    handle_syscall(pid, &process_state->state, &info);
			    break;
			default:
			    error(EXIT_FAILURE, errno,
				  "expected PTRACE_SYSCALL_INFO_ENTRY or PTRACE_SYSCALL_INFO_EXIT\n");
		    }

		    break;
		case SIGSTOP:
		    ++running;

		    PROCESS_INFO *pi = next_pinfo();

		    pi->pid = pid;
		    pi->finfo_size = DEFAULT_FINFO_SIZE;
		    pi->finfo = calloc(pi->finfo_size, sizeof (FILE_INFO));
		    pi->numfinfo = -1;
		    break;
	    }

	    // Restarting process 
	    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
		error(EXIT_FAILURE, errno, "failed restarting process");
	    }
	} else if (WIFEXITED(status))  // child process exited
	{
	    --running;
	    record_process_end(pid);
	} else {
	    error(EXIT_FAILURE, errno, "expected stop or tracee death\n");
	}
    }
}

void
trace(pid_t pid, char **envp)
{
    PROCESS_INFO *pi;

    pi = next_pinfo();
    pi->pid = pid;

    pi->finfo_size = DEFAULT_FINFO_SIZE;
    pi->finfo = calloc(pi->finfo_size, sizeof (FILE_INFO));
    pi->numfinfo = -1;

    tracer_main(pid, envp);
}

void
run_tracee(char **av)
{
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
    execvp(*av, av);
    error(EXIT_FAILURE, errno, "after child exec()");
}

void
run_and_record_fnames(char **av, char **envp)
{
    pid_t pid;

    pid = fork();
    if (pid < 0)
	error(EXIT_FAILURE, errno, "in original fork()");
    else if (pid == 0)
	run_tracee(av);

    init_pinfo();
    trace(pid, envp);
}


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
    if (numpinfo == pinfo_size - 1) {
	pinfo_size *= 2;
	pinfo = reallocarray(pinfo, pinfo_size, sizeof (PROCESS_INFO));
	if (pinfo == NULL)
	    error(EXIT_FAILURE, errno, "reallocating process info array");
    }

    return pinfo + (++numpinfo);
}

FILE_INFO *
finfo_at(PROCESS_INFO *pi, int index)
{
    if (index >= pi->finfo_size) {
	int prev_size = pi->finfo_size;

	do {
	    pi->finfo_size *= 2;
	} while (index >= pi->finfo_size);

	pi->finfo = reallocarray(pi->finfo, pi->finfo_size, sizeof (FILE_INFO));
	if (pi->finfo == NULL) {
	    error(EXIT_FAILURE, errno,
		  "reallocating file info array in process %d", pi->pid);
	}
	memset(pi->finfo + prev_size, 0, pi->finfo_size - prev_size);
    }

    return pi->finfo + index;
}

char *
get_str_from_process(pid_t pid, void *addr)
{
    static char buf[PATH_MAX];
    char *dest = buf;
    union {
	long lval;
	char cval[sizeof (long)];
    } data;

    size_t i = 0;

    do {
	data.lval =
		ptrace(PTRACE_PEEKDATA, pid, addr + i * sizeof (long), NULL);
	for (int j = 0; j < sizeof (long); j++) {
	    *dest++ = data.cval[j];
	    if (data.cval[j] == 0)
		break;
	}
	++i;
    } while (dest[-1]);

    return strdup(buf);
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
handle_syscall(PROCESS_INFO *pi, const struct ptrace_syscall_info *entry,
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
	    path = (void *) entry->entry.args[0];
	    flags = (int) entry->entry.args[1];

	    finfo = finfo_at(pi, fd);

	    finfo->path = get_str_from_process(pi->pid, path);
	    finfo->purpose = flags;
	    sprintf(finfo->outname, "f%d", numfinfo++);
	    break;
	case SYS_creat:
	    // int creat(const char *pathname, ...);
	    fd = (int) exit->exit.rval;
	    path = (void *) entry->entry.args[0];

	    finfo = finfo_at(pi, fd);

	    finfo->path = get_str_from_process(pi->pid, path);
	    finfo->purpose = O_CREAT | O_WRONLY | O_TRUNC;
	    sprintf(finfo->outname, "f%d", numfinfo++);
	    break;
	case SYS_openat:
	    // int openat(int dirfd, const char *pathname, int flags, ...);
	    fd = (int) exit->exit.rval;
	    dirfd = (int) entry->entry.args[0];
	    path = (void *) entry->entry.args[1];
	    flags = (int) entry->entry.args[2];

	    finfo = finfo_at(pi, fd);
	    char *rpath = get_str_from_process(pi->pid, path);

	    finfo->purpose = flags;
	    sprintf(finfo->outname, "f%d", numfinfo++);

	    if (dirfd == AT_FDCWD || *rpath == '/') {
		// If it's an absolute path or relative to cwd
		finfo->path = rpath;
		break;
	    }

	    dir = pi->finfo + dirfd;
	    long dir_path_length = strlen(dir->path);

	    char *buf = (char *) malloc(dir_path_length + strlen(rpath) + 2);

	    // one for '/' and one for null terminator

	    strcpy(buf, dir->path);
	    buf[dir_path_length] = '/';
	    strcpy(buf + dir_path_length + 1, rpath);
	    free(rpath);

	    finfo->path = buf;
	    break;
	case SYS_close:
	    // int close(int fd);
	    fd = (int) entry->entry.args[0];

	    finfo = pi->finfo + fd;

	    if (finfo->path != (char *) 0) {
		finfo->hash = get_file_hash(finfo->path);
		record_fileuse(pi->outname, finfo->outname, finfo->path,
			       finfo->purpose, finfo->hash);

		free(finfo->path);
		free(finfo->hash);
		memset(finfo, 0, sizeof (FILE_INFO));
	    }
	    break;
	case SYS_execve:
	    // int execve(const char *pathname, char *const argv[],
	    // char *const envp[]);
	    record_process_start(pi->pid, pi->outname);
	    break;
	case SYS_execveat:
	    // int execveat(int dirfd, const char *pathname,
	    // const char *const argv[], const char * const envp[],
	    // int flags);
	    record_process_start(pi->pid, pi->outname);
	    break;
	default:
	    return;
    }
}

static void
tracer_main(pid_t pid, char **envp)
{
    waitpid(pid, NULL, 0);

    record_process_start(pid, find(pid)->outname);
    record_process_env(find(pid)->outname, envp);

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
			    handle_syscall(process_state, &process_state->state,
					   &info);
			    break;
			default:
			    error(EXIT_FAILURE, errno,
				  "expected PTRACE_SYSCALL_INFO_ENTRY or PTRACE_SYSCALL_INFO_EXIT\n");
		    }

		    break;
		case SIGSTOP:
		    ++running;

		    PROCESS_INFO *pi = next_pinfo();

		    sprintf(pi->outname, "p%d", numpinfo);
		    pi->pid = pid;
		    pi->finfo_size = DEFAULT_FINFO_SIZE;
		    pi->finfo = calloc(pi->finfo_size, sizeof (FILE_INFO));
		    break;
	    }

	    // Restarting process 
	    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
		error(EXIT_FAILURE, errno, "failed restarting process");
	    }
	} else if (WIFEXITED(status))  // child process exited
	{
	    --running;
	    record_process_end(find(pid)->outname);
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

    sprintf(pi->outname, "p%d", numpinfo);
    pi->pid = pid;
    pi->finfo_size = DEFAULT_FINFO_SIZE;
    pi->finfo = calloc(pi->finfo_size, sizeof (FILE_INFO));

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

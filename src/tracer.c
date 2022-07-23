
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
#include	<linux/ptrace.h>

#include	<sys/signal.h>
#include	<sys/syscall.h>
#include	<sys/wait.h>

#include	"types.h"

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

uint8_t *hash_file(char *);

static void
handle_close(FILE_INFO *f)
{
    f->hash = hash_file(f->path);
}

static void
handle_open(pid_t pid, FILE_INFO *finfo, const unsigned long long *args)
{
    finfo->path = get_str_from_process(pid, (void *) args[0]);
    finfo->purpose = args[1];
}

static void
handle_openat(pid_t pid, FILE_INFO *finfo, const unsigned long long *args)
{
    char *rpath = get_str_from_process(pid, (void *) args[1]);

    finfo->purpose = args[2];

    if ((int) args[0] == AT_FDCWD || *rpath == '/') {	// If it's an
	// absolute path or
	// relative to cwd
	finfo->path = rpath;
	return;
    }

    FILE_INFO *dir = pinfo->finfo + pinfo->open_files[args[0]];
    long dir_path_length = strlen(dir->path);

    char *buf = (char *) malloc(dir_path_length + strlen(rpath) + 2);	// one 
									// 
    // for 
    // '/' 
    // and 
    // one 
    // for 
    // null 
    // terminator

    strcpy(buf, dir->path);
    buf[dir_path_length] = '/';
    strcpy(buf + dir_path_length + 1, rpath);
    free(rpath);

    finfo->path = buf;
}

static void
handle_syscall(pid_t pid, const struct ptrace_syscall_info *entry,
	       const struct ptrace_syscall_info *exit)
{
    if (exit->exit.rval < 0) {
	return;			       // return on syscall failure
    }

    const int syscall = entry->entry.nr;

    if (syscall != SYS_open && syscall != SYS_creat && syscall != SYS_openat
	&& syscall != SYS_close) {
	return;			       // return if we don't care about
	// tracking said syscall
    }

    if (syscall == SYS_close) {
	handle_close(pinfo->finfo + pinfo->open_files[entry->entry.args[0]]);
	return;
    }

    const int fd = exit->exit.rval;

    if (fd >= 1024)		       // more than 1024 files open
	// concurrently
    {
	error(EXIT_FAILURE, errno,
	      "limit of 1024 open files exceeded for process %d", pid);
    }

    PROCESS_INFO *pinfo = find(pid);
    FILE_INFO *finfo = next_finfo(pinfo);

    pinfo->open_files[fd] = pinfo->numfinfo;

    if (syscall == SYS_open || syscall == SYS_creat) {
	handle_open(pid, finfo, entry->entry.args);
    }

    handle_openat(pid, finfo, entry->entry.args);
}

static void
tracer_main(pid_t pid)
{
    waitpid(pid, NULL, 0);
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
		case SIGTRAP:	       // Caused from fork/vfork/clone/.
		    // Ignored, the child will be handled
		    // at SYGSTOP instead.
		    // Reading and ignoring clone/fork/vfork syscall exit
		    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0
			|| waitpid(pid, NULL, 0) < 0) {
			error(EXIT_FAILURE, errno,
			      "PTRACE_SYSCALL failed on fork/vfork/clone exit");
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
		default:
		    error(EXIT_FAILURE, errno, "unexpected signal\n");
	    }

	    // Restarting process 
	    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
		error(EXIT_FAILURE, errno, "failed restarting process");
	    }
	} else if (WIFEXITED(status))  // child process exited
	{
	    --running;
	} else {
	    error(EXIT_FAILURE, errno, "expected stop or tracee death\n");
	}
    }
}

void
trace(pid_t pid)
{
    PROCESS_INFO *pi;

    pi = next_pinfo();
    pi->pid = pid;

    pi->finfo_size = DEFAULT_FINFO_SIZE;
    pi->finfo = calloc(pi->finfo_size, sizeof (FILE_INFO));
    pi->numfinfo = -1;

    tracer_main(pid);
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

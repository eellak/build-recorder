
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
#include	<stddef.h>
#include	<string.h>
#include	<unistd.h>
#include	<fcntl.h>

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

FILE_INFO *finfo;
int numfinfo;
int finfo_size;

#define	DEFAULT_PINFO_SIZE	32
#define	DEFAULT_FINFO_SIZE	32

/*
 * memory allocators for pinfo
 */

void
init(void)
{
    pinfo_size = DEFAULT_PINFO_SIZE;
    pinfo = calloc(pinfo_size, sizeof (PROCESS_INFO));
    numpinfo = -1;

    finfo_size = DEFAULT_FINFO_SIZE;
    finfo = calloc(finfo_size, sizeof (FILE_INFO));
    numfinfo = -1;
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
next_finfo(void)
{
    if (numfinfo == finfo_size - 1) {
	finfo_size *= 2;
	finfo = reallocarray(finfo, finfo_size, sizeof (FILE_INFO));
	if (finfo == NULL)
	    error(EXIT_FAILURE, errno, "reallocating file info array");
    }

    return finfo + (++numfinfo);
}

void
pinfo_new(PROCESS_INFO *self, pid_t pid, char ignore_one_sigstop)
{
    sprintf(self->outname, ":p%d", numpinfo);
    self->pid = pid;
    self->finfo_size = DEFAULT_FINFO_SIZE;
    self->finfo = calloc(self->finfo_size, sizeof (FILE_INFO));
    self->ignore_one_sigstop = ignore_one_sigstop;
}

void
finfo_new(FILE_INFO *self, char *path, char *abspath, char *hash)
{
    self->was_hash_printed = 0;
    self->path = path;
    self->abspath = abspath;
    self->hash = hash;
    sprintf(self->outname, ":f%d", numfinfo);

    record_file(self->outname, path, abspath);
}

PROCESS_INFO *
find_pinfo(pid_t pid)
{
    int i = numpinfo;

    while (i >= 0 && pinfo[i].pid != pid) {
	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return pinfo + i;
}

FILE_INFO *
find_finfo(char *abspath)
{
    int i = numfinfo;

    while (i >= 0 && strcmp(abspath, finfo[i].abspath)) {
	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return finfo + i;
}

int *
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

	for (int i = prev_size; i < pi->finfo_size; ++i) {
	    pi->finfo[i] = -1;
	}
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

char *
absolutepath(pid_t pid, int dirfd, char *addr)
{
    char symbpath[PATH_MAX];

    if (*addr == '/') {
	return realpath(addr, NULL);
    }
    if (dirfd == AT_FDCWD) {
	sprintf(symbpath, "/proc/%d/cwd/%s", pid, addr);
	return realpath(symbpath, NULL);
    }

    sprintf(symbpath, "/proc/%d/fd/%d/%s", pid, dirfd, addr);
    return realpath(symbpath, NULL);
}

char *
find_in_path(char *path)
{
    static char buf[PATH_MAX];
    char *ret;
    char *PATH = strdup(getenv("PATH"));
    char *it = PATH;
    char *last;

    do {
	last = strchr(it, ':');
	if (last) {
	    *last = '\0';
	}

	sprintf(buf, "%s/%s", it, path);
	ret = realpath(buf, NULL);
	if (!ret && (errno != 0 && errno != ENOENT)) {
	    error(EXIT_FAILURE, errno, "on find_in_path realpath");
	}
	it = last + 1;
    } while (last != NULL && ret == NULL);

    free(PATH);

    return ret;
}

static void
handle_open(PROCESS_INFO *pi, int fd, int dirfd, void *path, int purpose)
{
    path = get_str_from_process(pi->pid, path);
    char *abspath = absolutepath(pi->pid, dirfd, path);

    if (abspath == NULL)
	error(EXIT_FAILURE, errno, "on handle_open absolutepath");

    FILE_INFO *f = NULL;

    if ((purpose & O_ACCMODE) == O_RDONLY) {
	f = find_finfo(abspath);
    }

    if (!f) {
	f = next_finfo();
	char *hash = get_file_hash(abspath);

	finfo_new(f, path, abspath, hash);
    } else {
	free(path);
	free(abspath);
    }
    *finfo_at(pi, fd) = f - finfo;

    record_fileuse(pi->outname, f->outname, purpose);
    if (!f->was_hash_printed && (purpose & O_ACCMODE) == O_RDONLY) {
	f->was_hash_printed = 1;
	record_hash(f->outname, f->hash);
    }
}

static void
handle_execve(PROCESS_INFO *pi, int dirfd, char *path)
{
    record_process_start(pi->pid, pi->outname);

    char *abspath = absolutepath(pi->pid, dirfd, path);

    if (!abspath) {
	if (errno != ENOENT) {
	    error(EXIT_FAILURE, errno, "on handle_execve absolutepath");
	}

	abspath = find_in_path(path);

	if (!abspath) {
	    error(EXIT_FAILURE, errno, "on handle_execve find_in_path");
	}
    }

    FILE_INFO *f;

    if (!(f = find_finfo(abspath))) {
	f = next_finfo();
	char *hash = get_file_hash(abspath);

	finfo_new(f, path, abspath, hash);
	record_hash(f->outname, f->hash);
	f->was_hash_printed = 1;
    } else {
	free(abspath);
	free(path);
    }

    record_exec(pi->outname, f->outname);
}

static void
handle_rename_entry(PROCESS_INFO *pi, int olddirfd, char *oldpath)
{
    char *abspath = absolutepath(pi->pid, olddirfd, oldpath);

    FILE_INFO *f = find_finfo(abspath);

    if (!f) {
	f = next_finfo();
	char *hash = get_file_hash(abspath);

	finfo_new(f, oldpath, abspath, hash);
    } else {
	free(oldpath);
	free(abspath);
    }

    pi->entry_info = (void *) (f - finfo);
    if (pi->entry_info == NULL)
	error(EXIT_FAILURE, errno, "on handle_rename_entry absolutepath");
}

static void
handle_rename_exit(PROCESS_INFO *pi, int newdirfd, char *newpath)
{
    FILE_INFO *from = finfo + (ptrdiff_t) pi->entry_info;

    char *abspath = absolutepath(pi->pid, newdirfd, newpath);

    FILE_INFO *to = next_finfo();

    finfo_new(to, newpath, abspath, from->hash);

    record_rename(pi->outname, from->outname, to->outname);
}

static void
handle_create_process(PROCESS_INFO *pi, pid_t child)
{
    PROCESS_INFO *child_pi = find_pinfo(child);

    if (!child_pi) {
	child_pi = next_pinfo();
	pinfo_new(child_pi, child, 1);
    }

    record_process_create(pi->outname, child_pi->outname);
}

static void
handle_syscall_entry(PROCESS_INFO *pi, const struct ptrace_syscall_info *entry)
{
    int olddirfd;
    char *oldpath;

    switch (entry->entry.nr) {
	case SYS_rename:
	    // int rename(const char *oldpath, const char *newpath);
	    oldpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[0]);
	    handle_rename_entry(pi, AT_FDCWD, oldpath);
	    break;
	case SYS_renameat:
	    // int renameat(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath);
	    olddirfd = entry->entry.args[0];
	    oldpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[1]);
	    handle_rename_entry(pi, olddirfd, oldpath);
	    break;
	case SYS_renameat2:
	    // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath, unsigned int flags);
	    olddirfd = entry->entry.args[0];
	    oldpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[1]);
	    handle_rename_entry(pi, olddirfd, oldpath);
	    break;
	case SYS_execve:
	    pi->entry_info =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[0]);
	    break;
	case SYS_execveat:
	    pi->entry_info =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[1]);
	    break;
    }
}

static void
handle_syscall_exit(PROCESS_INFO *pi, const struct ptrace_syscall_info *entry,
		    const struct ptrace_syscall_info *exit)
{
    if (exit->exit.rval < 0) {
	return;			       // return on syscall failure
    }

    int fd;
    void *path;
    int flags;
    int dirfd;
    FILE_INFO *f;
    int newdirfd;
    char *newpath;

    switch (entry->entry.nr) {
	case SYS_open:
	    // int open(const char *pathname, int flags, ...);
	    fd = (int) exit->exit.rval;
	    path = (void *) entry->entry.args[0];
	    flags = (int) entry->entry.args[1];

	    handle_open(pi, fd, AT_FDCWD, path, flags);
	    break;
	case SYS_creat:
	    // int creat(const char *pathname, ...);
	    fd = (int) exit->exit.rval;
	    path = (void *) entry->entry.args[0];

	    handle_open(pi, fd, AT_FDCWD, path, O_CREAT | O_WRONLY | O_TRUNC);
	    break;
	case SYS_openat:
	    // int openat(int dirfd, const char *pathname, int flags, ...);
	    fd = (int) exit->exit.rval;
	    dirfd = (int) entry->entry.args[0];
	    path = (void *) entry->entry.args[1];
	    flags = (int) entry->entry.args[2];

	    handle_open(pi, fd, dirfd, path, flags);
	    break;
	case SYS_close:
	    // int close(int fd);
	    fd = (int) entry->entry.args[0];

	    if (pi->finfo[fd] != -1) {
		f = finfo + pi->finfo[fd];

		if (!f->was_hash_printed) {
		    f->hash = get_file_hash(f->abspath);
		    record_hash(f->outname, f->hash);
		    f->was_hash_printed = 1;
		}

		pi->finfo[fd] = -1;
	    }
	    break;
	case SYS_execve:
	    // int execve(const char *pathname, char *const argv[],
	    // char *const envp[]);
	    path = pi->entry_info;

	    handle_execve(pi, AT_FDCWD, path);
	    break;
	case SYS_execveat:
	    // int execveat(int dirfd, const char *pathname,
	    // const char *const argv[], const char * const envp[],
	    // int flags);
	    dirfd = entry->entry.args[0];
	    path = pi->entry_info;

	    handle_execve(pi, dirfd, path);
	    break;
	case SYS_rename:
	    // int rename(const char *oldpath, const char *newpath);
	    newpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[1]);

	    handle_rename_exit(pi, AT_FDCWD, newpath);
	    break;
	case SYS_renameat:
	    // int renameat(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath);
	    newdirfd = entry->entry.args[2];
	    newpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[3]);

	    handle_rename_exit(pi, newdirfd, newpath);
	    break;
	case SYS_renameat2:
	    // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath, unsigned int flags);
	    newdirfd = entry->entry.args[2];
	    newpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[3]);

	    handle_rename_exit(pi, newdirfd, newpath);
	    break;
	case SYS_fork:
	    // pid_t fork(void);
	    handle_create_process(pi, exit->exit.rval);
	    break;
	case SYS_vfork:
	    // pid_t vfork(void);
	    handle_create_process(pi, exit->exit.rval);
	    break;
	case SYS_clone:
	    // int clone(...);
	    handle_create_process(pi, exit->exit.rval);
	    break;
    }
}

static void
tracer_main(PROCESS_INFO *pi, char *path, char **envp)
{
    waitpid(pi->pid, NULL, 0);

    record_process_env(pi->outname, envp);
    handle_execve(pi, AT_FDCWD, path);

    ptrace(PTRACE_SETOPTIONS, pi->pid, NULL,	// Options are inherited
	   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    struct ptrace_syscall_info info;
    static size_t running = 1;

    int status;
    int pid;
    PROCESS_INFO *process_state;

    // Starting tracee
    if (ptrace(PTRACE_SYSCALL, pi->pid, NULL, NULL) < 0) {
	error(EXIT_FAILURE, errno, "tracee PTRACE_SYSCALL failed");
    }

    while (running) {
	pid = wait(&status);

	if (pid < 0) {
	    error(EXIT_FAILURE, errno, "wait failed");
	}

	unsigned int restart_sig = 0;

	if (WIFSTOPPED(status)) {
	    switch (WSTOPSIG(status)) {
		case SIGTRAP | 0x80:
		    process_state = find_pinfo(pid);
		    if (!process_state) {
			error(EXIT_FAILURE, 0, "find_pinfo on syscall sigtrap");
		    }

		    if (ptrace
			(PTRACE_GET_SYSCALL_INFO, pid, (void *) sizeof (info),
			 &info) < 0) {
			error(EXIT_FAILURE, errno,
			      "tracee PTRACE_GET_SYSCALL_INFO failed");
		    }

		    switch (info.op) {
			case PTRACE_SYSCALL_INFO_ENTRY:
			    process_state->state = info;
			    handle_syscall_entry(process_state, &info);
			    break;
			case PTRACE_SYSCALL_INFO_EXIT:
			    handle_syscall_exit(process_state,
						&process_state->state, &info);
			    break;
			default:
			    error(EXIT_FAILURE, errno,
				  "expected PTRACE_SYSCALL_INFO_ENTRY or PTRACE_SYSCALL_INFO_EXIT\n");
		    }

		    break;
		case SIGSTOP:
		    // We only want to ignore post-attach SIGSTOP, for the
		    // rest we shouldn't mess with.
		    if ((process_state = find_pinfo(pid))) {
			if (process_state->ignore_one_sigstop == 0) {
			    restart_sig = WSTOPSIG(status);
			} else {
			    ++running;
			    process_state->ignore_one_sigstop = 0;
			}
		    } else {
			++running;
			PROCESS_INFO *pi = next_pinfo();

			pinfo_new(pi, pid, 0);
		    }
		    break;
		case SIGTRAP:
		    // Also ignore SIGTRAPs since they are
		    // generated by ptrace(2)
		    break;
		default:
		    restart_sig = WSTOPSIG(status);
	    }

	    // Restarting process 
	    if (ptrace(PTRACE_SYSCALL, pid, NULL, restart_sig) < 0) {
		error(EXIT_FAILURE, errno, "failed restarting process");
	    }
	} else if (WIFEXITED(status))  // child process exited
	{
	    --running;

	    process_state = find_pinfo(pid);
	    if (!process_state) {
		error(EXIT_FAILURE, 0, "find_pinfo on WIFEXITED");
	    }

	    record_process_end(process_state->outname);
	}
    }
}

void
trace(pid_t pid, char *path, char **envp)
{
    PROCESS_INFO *pi;

    pi = next_pinfo();

    pinfo_new(pi, pid, 0);

    tracer_main(pi, path, envp);
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

    init();
    trace(pid, *av, envp);
}

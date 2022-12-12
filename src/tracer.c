
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
handle_open(CONTEXT *ctx, PROCESS_INFO *pi, int fd, int dirfd, void *path,
	    int purpose)
{
    path = get_str_from_process(pi->pid, path);
    char *abspath = absolutepath(pi->pid, dirfd, path);

    if (abspath == NULL)
	error(EXIT_FAILURE, errno, "on handle_open absolutepath");

    char *hash = NULL;

    FILE_INFO *f = NULL;

    if ((purpose & O_ACCMODE) == O_RDONLY) {
	hash = get_file_hash(abspath);
	f = context_find_finfo(ctx, abspath, hash);
    }

    if (!f) {
	f = context_next_finfo(ctx);
	finfo_new(f, ctx->numfinfo, path, abspath, hash);
	record_file(f->outname, f->path, f->abspath);
    } else {
	free(path);
	free(abspath);
	free(hash);
    }
    *pinfo_finfo_at(pi, fd) = f - ctx->finfo;

    record_fileuse(pi->outname, f->outname, purpose);
    if (!f->was_hash_printed && (purpose & O_ACCMODE) == O_RDONLY) {
	f->was_hash_printed = 1;
	record_hash(f->outname, hash);
    }
}

static void
handle_execve(CONTEXT *ctx, PROCESS_INFO *pi, int dirfd, char *path)
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

    char *hash = get_file_hash(abspath);

    FILE_INFO *f;

    if (!(f = context_find_finfo(ctx, abspath, hash))) {
	f = context_next_finfo(ctx);

	finfo_new(f, ctx->numfinfo, path, abspath, hash);
	record_file(f->outname, f->path, f->abspath);
	record_hash(f->outname, f->hash);
	f->was_hash_printed = 1;
    } else {
	free(abspath);
	free(hash);
	free(path);
    }

    record_exec(pi->outname, f->outname);
}

static void
handle_rename_entry(CONTEXT *ctx, PROCESS_INFO *pi, int olddirfd, char *oldpath)
{
    char *abspath = absolutepath(pi->pid, olddirfd, oldpath);
    char *hash = get_file_hash(abspath);

    FILE_INFO *f = context_find_finfo(ctx, abspath, hash);

    if (!f) {
	f = context_next_finfo(ctx);
	finfo_new(f, ctx->numfinfo, oldpath, abspath, hash);
	record_file(f->outname, f->path, f->abspath);
    } else {
	free(oldpath);
	free(abspath);
	free(hash);
    }

    pi->entry_info = (void *) (f - ctx->finfo);
    if (pi->entry_info == NULL)
	error(EXIT_FAILURE, errno, "on handle_rename_entry absolutepath");
}

static void
handle_rename_exit(CONTEXT *ctx, PROCESS_INFO *pi, int newdirfd, char *newpath)
{
    FILE_INFO *from = ctx->finfo + (ptrdiff_t) pi->entry_info;

    char *abspath = absolutepath(pi->pid, newdirfd, newpath);

    FILE_INFO *to = context_next_finfo(ctx);

    finfo_new(to, ctx->numfinfo, newpath, abspath, from->hash);
    record_file(to->outname, to->path, to->abspath);

    record_rename(pi->outname, from->outname, to->outname);
}

static void
handle_create_process(CONTEXT *ctx, PROCESS_INFO *pi, pid_t child)
{
    PROCESS_INFO *child_pi = context_find_pinfo(ctx, child);

    if (!child_pi) {
	child_pi = context_next_pinfo(ctx);
	pinfo_new(child_pi, ctx->numpinfo, child, 1);
    }

    record_process_create(pi->outname, child_pi->outname);
}

static void
handle_syscall_entry(CONTEXT *ctx, PROCESS_INFO *pi,
		     const struct ptrace_syscall_info *entry)
{
    int olddirfd;
    char *oldpath;

    switch (entry->entry.nr) {
	case SYS_rename:
	    // int rename(const char *oldpath, const char *newpath);
	    oldpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[0]);
	    handle_rename_entry(ctx, pi, AT_FDCWD, oldpath);
	    break;
	case SYS_renameat:
	    // int renameat(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath);
	    olddirfd = entry->entry.args[0];
	    oldpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[1]);
	    handle_rename_entry(ctx, pi, olddirfd, oldpath);
	    break;
	case SYS_renameat2:
	    // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath, unsigned int flags);
	    olddirfd = entry->entry.args[0];
	    oldpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[1]);
	    handle_rename_entry(ctx, pi, olddirfd, oldpath);
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
handle_syscall_exit(CONTEXT *ctx, PROCESS_INFO *pi,
		    const struct ptrace_syscall_info *entry,
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

	    handle_open(ctx, pi, fd, AT_FDCWD, path, flags);
	    break;
	case SYS_creat:
	    // int creat(const char *pathname, ...);
	    fd = (int) exit->exit.rval;
	    path = (void *) entry->entry.args[0];

	    handle_open(ctx, pi, fd, AT_FDCWD, path,
			O_CREAT | O_WRONLY | O_TRUNC);
	    break;
	case SYS_openat:
	    // int openat(int dirfd, const char *pathname, int flags, ...);
	    fd = (int) exit->exit.rval;
	    dirfd = (int) entry->entry.args[0];
	    path = (void *) entry->entry.args[1];
	    flags = (int) entry->entry.args[2];

	    handle_open(ctx, pi, fd, dirfd, path, flags);
	    break;
	case SYS_close:
	    // int close(int fd);
	    fd = (int) entry->entry.args[0];

	    if (pi->finfo[fd] != -1) {
		f = ctx->finfo + pi->finfo[fd];

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

	    handle_execve(ctx, pi, AT_FDCWD, path);
	    break;
	case SYS_execveat:
	    // int execveat(int dirfd, const char *pathname,
	    // const char *const argv[], const char * const envp[],
	    // int flags);
	    dirfd = entry->entry.args[0];
	    path = pi->entry_info;

	    handle_execve(ctx, pi, dirfd, path);
	    break;
	case SYS_rename:
	    // int rename(const char *oldpath, const char *newpath);
	    newpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[1]);

	    handle_rename_exit(ctx, pi, AT_FDCWD, newpath);
	    break;
	case SYS_renameat:
	    // int renameat(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath);
	    newdirfd = entry->entry.args[2];
	    newpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[3]);

	    handle_rename_exit(ctx, pi, newdirfd, newpath);
	    break;
	case SYS_renameat2:
	    // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath, unsigned int flags);
	    newdirfd = entry->entry.args[2];
	    newpath =
		    get_str_from_process(pi->pid,
					 (void *) entry->entry.args[3]);

	    handle_rename_exit(ctx, pi, newdirfd, newpath);
	    break;
	case SYS_fork:
	    // pid_t fork(void);
	    handle_create_process(ctx, pi, exit->exit.rval);
	    break;
	case SYS_vfork:
	    // pid_t vfork(void);
	    handle_create_process(ctx, pi, exit->exit.rval);
	    break;
	case SYS_clone:
	    // int clone(...);
	    handle_create_process(ctx, pi, exit->exit.rval);
	    break;
    }
}

static void
tracer_main(CONTEXT *ctx, PROCESS_INFO *pi, char *path, char **envp)
{
    waitpid(pi->pid, NULL, 0);

    record_process_env(pi->outname, envp);
    handle_execve(ctx, pi, AT_FDCWD, path);

    ptrace(PTRACE_SETOPTIONS, pi->pid, NULL,	// Options are inherited
	   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    struct ptrace_syscall_info info;
    static size_t running = 1;

    int status;
    int pid;

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
		    pi = context_find_pinfo(ctx, pid);
		    if (!pi) {
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
			    pi->state = info;
			    handle_syscall_entry(ctx, pi, &info);
			    break;
			case PTRACE_SYSCALL_INFO_EXIT:
			    handle_syscall_exit(ctx, pi, &pi->state, &info);
			    break;
			default:
			    error(EXIT_FAILURE, errno,
				  "expected PTRACE_SYSCALL_INFO_ENTRY or PTRACE_SYSCALL_INFO_EXIT\n");
		    }

		    break;
		case SIGSTOP:
		    // We only want to ignore post-attach SIGSTOP, for the
		    // rest we shouldn't mess with.
		    if ((pi = context_find_pinfo(ctx, pid))) {
			if (pi->ignore_one_sigstop == 0) {
			    restart_sig = WSTOPSIG(status);
			} else {
			    ++running;
			    pi->ignore_one_sigstop = 0;
			}
		    } else {
			++running;
			PROCESS_INFO *pi = context_next_pinfo(ctx);

			pinfo_new(pi, ctx->numpinfo, pid, 0);
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

	    pi = context_find_pinfo(ctx, pid);
	    if (!pi) {
		error(EXIT_FAILURE, 0, "find_pinfo on WIFEXITED");
	    }

	    record_process_end(pi->outname);
	}
    }
}

void
trace(pid_t pid, char *path, char **envp)
{
    CONTEXT ctx;

    context_init(&ctx);

    PROCESS_INFO *pi;

    pi = context_next_pinfo(&ctx);

    pinfo_new(pi, ctx.numpinfo, pid, 0);

    tracer_main(&ctx, pi, path, envp);
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

    trace(pid, *av, envp);
}

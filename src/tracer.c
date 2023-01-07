
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

#include	"hashmap.h"
#include	"hash.h"
#include	"record.h"

/*
 * Variables for the list of processes,
 * its size and the array size. As well as
 * a list of their respective pids with the
 * same size and array size.
 */

int *pids;
PROCESS_INFO *pinfo;
int numpinfo;
int pinfo_size;

/*
 * A hashtable that maps keys to values.
 * Keys being the string concatenation of abspath and hash(if not null, in case of folders),
 * Values being a FILE_INFO structure.
 */
hashmap finfo;

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
    pids = malloc(pinfo_size * sizeof (int));
    numpinfo = -1;

    hashmap_new(&finfo);
}

PROCESS_INFO *
next_pinfo(pid_t pid)
{
    if (numpinfo == pinfo_size - 1) {
	pinfo_size *= 2;
	pinfo = reallocarray(pinfo, pinfo_size, sizeof (PROCESS_INFO));
	if (pinfo == NULL)
	    error(EXIT_FAILURE, errno, "reallocating process info array");

	pids = reallocarray(pids, pinfo_size, sizeof (int));
	if (pids == NULL)
	    error(EXIT_FAILURE, errno, "reallocating pids array");
    }

    pids[numpinfo + 1] = pid;
    return pinfo + (++numpinfo);
}

void
pinfo_new(PROCESS_INFO *self, char ignore_one_sigstop)
{
    static int pcount = 0;

    sprintf(self->outname, ":p%d", pcount++);
    self->finfo_size = DEFAULT_FINFO_SIZE;
    self->numfinfo = -1;
    self->finfo = malloc(self->finfo_size * sizeof (FILE_INFO));
    self->fds = malloc(self->finfo_size * sizeof (int));
    self->ignore_one_sigstop = ignore_one_sigstop;
}

void
finfo_new(FILE_INFO *self)
{
    static int fcount = 0;

    sprintf(self->outname, ":f%d", fcount++);
}

PROCESS_INFO *
find_pinfo(pid_t pid)
{
    int i = numpinfo;

    while (i >= 0 && pids[i] != pid) {
	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return pinfo + i;
}

FILE_WRITE *
pinfo_find_finfo(PROCESS_INFO *self, int fd)
{
    int i = self->numfinfo;

    while (i >= 0 && self->fds[i] != fd) {
	--i;
    }

    if (i < 0) {
	return NULL;
    }

    return self->finfo + i;
}

FILE_WRITE *
pinfo_next_finfo(PROCESS_INFO *self, int fd)
{
    if (self->numfinfo == self->finfo_size - 1) {
	self->finfo_size *= 2;
	self->finfo =
		reallocarray(self->finfo, self->finfo_size,
			     sizeof (FILE_WRITE));
	self->fds = reallocarray(self->fds, self->finfo_size, sizeof (int));
	if (self->finfo == NULL)
	    error(EXIT_FAILURE, errno, "reallocating file info array");
    }

    self->fds[self->numfinfo + 1] = fd;
    return self->finfo + (++self->numfinfo);
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
		ptrace(PTRACE_PEEKDATA, pid, (char *) addr + i * sizeof (long),
		       NULL);
	for (unsigned j = 0; j < sizeof (long); j++) {
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

static char *
craft_key(const char *abspath, const char *hash)
{
    if (!hash)			       /* If it's a folder */
	return strdup(abspath);

    char *key = (char *) malloc(strlen(abspath) + SHA1_HEXBUF_LEN);

    strcpy(key, hash);
    strcat(key, abspath);
    return key;
}

static void
handle_open(pid_t pid, PROCESS_INFO *pi, int fd, int dirfd, void *path,
	    int purpose)
{
    path = get_str_from_process(pid, path);
    char *abspath = absolutepath(pid, dirfd, path);

    if (abspath == NULL)
	error(EXIT_FAILURE, errno, "on handle_open absolutepath");

    FILE_INFO *f = NULL;

    if ((purpose & O_ACCMODE) == O_RDONLY) {
	char *hash = get_file_hash(abspath);
	char *key = craft_key(abspath, hash);

	f = hashmap_insert(&finfo, key);
	if (!*(char *) f) {
	    finfo_new(f);
	    record_file(f->outname, path, abspath);
	    record_hash(f->outname, hash);
	} else {
	    free(key);
	}

	free(abspath);
	free(hash);
    } else {
	FILE_WRITE *fw = pinfo_next_finfo(pi, fd);

	f = &(fw->f);
	fw->abspath = abspath;

	finfo_new(f);
	record_file(f->outname, path, abspath);
    }

    record_fileuse(pi->outname, f->outname, purpose);

    free(path);
}

static void
handle_execve(pid_t pid, PROCESS_INFO *pi, int dirfd, char *path)
{
    record_process_start(pid, pi->outname);

    char *abspath = absolutepath(pid, dirfd, path);

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
    char *key = craft_key(abspath, hash);

    FILE_INFO *f = hashmap_insert(&finfo, key);

    if (!*(char *) f) {
	finfo_new(f);
	record_file(f->outname, path, abspath);
	record_hash(f->outname, hash);
    } else {
	free(key);
    }

    record_exec(pi->outname, f->outname);

    free(abspath);
    free(hash);
}

static void
handle_rename_entry(pid_t pid, PROCESS_INFO *pi, int olddirfd, char *oldpath)
{
    char *abspath = absolutepath(pid, olddirfd, oldpath);
    char *hash = get_file_hash(abspath);
    char *key = craft_key(abspath, hash);
    char *dup;			  /* Duplicate the key so we can pass it to
				     rename_exit */

    FILE_INFO *f = hashmap_insert(&finfo, key);

    if (!*(char *) f) {
	finfo_new(f);
	record_file(f->outname, oldpath, abspath);
	record_hash(f->outname, hash);
	dup = strdup(key);
    } else {
	dup = key;		       /* We can reuse that */
    }

    pi->entry_info = (void *) dup;

    free(oldpath);
    free(abspath);
    free(hash);
}

static void
handle_rename_exit(pid_t pid, PROCESS_INFO *pi, int newdirfd, char *newpath)
{
    char *fromkey = (char *) pi->entry_info;
    FILE_INFO *from = hashmap_insert(&finfo, fromkey);

    /* The first SHA1_HEXBUF_LEN(excluding the null byte) bytes are the hash */
    fromkey[SHA1_HEXBUF_LEN - 1] = 0;
    char *hash = fromkey;	  /* readability */

    char *abspath = absolutepath(pid, newdirfd, newpath);
    char *tokey = craft_key(abspath, hash);

    FILE_INFO *to = hashmap_insert(&finfo, tokey);

    finfo_new(to);
    record_file(to->outname, newpath, abspath);
    record_hash(to->outname, hash);

    record_rename(pi->outname, from->outname, to->outname);

    free(newpath);
    free(abspath);
    /* This also frees fromkey, since they point to the same buffer */
    free(hash);
}

static void
handle_create_process(PROCESS_INFO *pi, pid_t child)
{
    PROCESS_INFO *child_pi = find_pinfo(child);

    if (!child_pi) {
	child_pi = next_pinfo(child);
	pinfo_new(child_pi, 1);
    }

    record_process_create(pi->outname, child_pi->outname);
}

static void
handle_syscall_entry(pid_t pid, PROCESS_INFO *pi,
		     const struct ptrace_syscall_info *entry)
{
    int olddirfd;
    char *oldpath;

    switch (entry->entry.nr) {
	case SYS_rename:
	    // int rename(const char *oldpath, const char *newpath);
	    oldpath = get_str_from_process(pid, (void *) entry->entry.args[0]);
	    handle_rename_entry(pid, pi, AT_FDCWD, oldpath);
	    break;
	case SYS_renameat:
	    // int renameat(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath);
	    olddirfd = entry->entry.args[0];
	    oldpath = get_str_from_process(pid, (void *) entry->entry.args[1]);
	    handle_rename_entry(pid, pi, olddirfd, oldpath);
	    break;
	case SYS_renameat2:
	    // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath, unsigned int flags);
	    olddirfd = entry->entry.args[0];
	    oldpath = get_str_from_process(pid, (void *) entry->entry.args[1]);
	    handle_rename_entry(pid, pi, olddirfd, oldpath);
	    break;
	case SYS_execve:
	    pi->entry_info =
		    get_str_from_process(pid, (void *) entry->entry.args[0]);
	    break;
	case SYS_execveat:
	    pi->entry_info =
		    get_str_from_process(pid, (void *) entry->entry.args[1]);
	    break;
    }
}

static void
handle_syscall_exit(pid_t pid, PROCESS_INFO *pi,
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
    FILE_WRITE *fw;
    int newdirfd;
    char *newpath;

    switch (entry->entry.nr) {
	case SYS_open:
	    // int open(const char *pathname, int flags, ...);
	    fd = (int) exit->exit.rval;
	    path = (void *) entry->entry.args[0];
	    flags = (int) entry->entry.args[1];

	    handle_open(pid, pi, fd, AT_FDCWD, path, flags);
	    break;
	case SYS_creat:
	    // int creat(const char *pathname, ...);
	    fd = (int) exit->exit.rval;
	    path = (void *) entry->entry.args[0];

	    handle_open(pid, pi, fd, AT_FDCWD, path,
			O_CREAT | O_WRONLY | O_TRUNC);
	    break;
	case SYS_openat:
	    // int openat(int dirfd, const char *pathname, int flags, ...);
	    fd = (int) exit->exit.rval;
	    dirfd = (int) entry->entry.args[0];
	    path = (void *) entry->entry.args[1];
	    flags = (int) entry->entry.args[2];

	    handle_open(pid, pi, fd, dirfd, path, flags);
	    break;
	case SYS_close:
	    // int close(int fd);
	    fd = (int) entry->entry.args[0];

	    fw = pinfo_find_finfo(pi, fd);
	    f = &(fw->f);

	    if (fw != NULL) {
		char *hash = get_file_hash(fw->abspath);

		record_hash(f->outname, hash);

		// Add it to global set
		*hashmap_insert(&finfo, craft_key(fw->abspath, hash)) = *f;

		// Remove the file from the process' list
		for (int i = fw - pi->finfo; i < pi->numfinfo; ++i) {
		    pi->finfo[i] = pi->finfo[i + 1];
		}

		for (int i = fw - pi->finfo; i < pi->numfinfo; ++i) {
		    pi->fds[i] = pi->fds[i + 1];
		}

		--pi->numfinfo;
	    }
	    break;
	case SYS_execve:
	    // int execve(const char *pathname, char *const argv[],
	    // char *const envp[]);
	    path = pi->entry_info;

	    handle_execve(pid, pi, AT_FDCWD, path);
	    free(path);
	    break;
	case SYS_execveat:
	    // int execveat(int dirfd, const char *pathname,
	    // const char *const argv[], const char * const envp[],
	    // int flags);
	    dirfd = entry->entry.args[0];
	    path = pi->entry_info;

	    handle_execve(pid, pi, dirfd, path);
	    free(path);
	    break;
	case SYS_rename:
	    // int rename(const char *oldpath, const char *newpath);
	    newpath = get_str_from_process(pid, (void *) entry->entry.args[1]);

	    handle_rename_exit(pid, pi, AT_FDCWD, newpath);
	    break;
	case SYS_renameat:
	    // int renameat(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath);
	    newdirfd = entry->entry.args[2];
	    newpath = get_str_from_process(pid, (void *) entry->entry.args[3]);

	    handle_rename_exit(pid, pi, newdirfd, newpath);
	    break;
	case SYS_renameat2:
	    // int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	    // const char *newpath, unsigned int flags);
	    newdirfd = entry->entry.args[2];
	    newpath = get_str_from_process(pid, (void *) entry->entry.args[3]);

	    handle_rename_exit(pid, pi, newdirfd, newpath);
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
tracer_main(pid_t pid, PROCESS_INFO *pi, char *path, char **envp)
{
    waitpid(pid, NULL, 0);

    record_process_env(pi->outname, envp);
    handle_execve(pid, pi, AT_FDCWD, path);

    ptrace(PTRACE_SETOPTIONS, pid, NULL,	// Options are inherited
	   PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
	   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);

    struct ptrace_syscall_info info;
    static size_t running = 1;

    int status;
    PROCESS_INFO *process_state;

    // Starting tracee
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
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
			    handle_syscall_entry(pid, process_state, &info);
			    break;
			case PTRACE_SYSCALL_INFO_EXIT:
			    handle_syscall_exit(pid, process_state,
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
			PROCESS_INFO *pi = next_pinfo(pid);

			pinfo_new(pi, 0);
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
	} else if (WIFEXITED(status)) {	// child process exited 
	    --running;

	    process_state = find_pinfo(pid);
	    if (!process_state) {
		error(EXIT_FAILURE, 0, "find_pinfo on WIFEXITED");
	    }

	    record_process_end(process_state->outname);

	    free(process_state->cmd_line);
	    free(process_state->finfo);
	    free(process_state->fds);

	    for (int i = process_state - pinfo; i < numpinfo; ++i) {
		pinfo[i] = pinfo[i + 1];
	    }
	    for (int i = process_state - pinfo; i < numpinfo; ++i) {
		pids[i] = pids[i + 1];
	    }
	    --numpinfo;
	}
    }
}

void
trace(pid_t pid, char *path, char **envp)
{
    PROCESS_INFO *pi;

    pi = next_pinfo(pid);

    pinfo_new(pi, 0);

    tracer_main(pid, pi, path, envp);
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

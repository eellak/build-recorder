
dnl Copyright (C) 2022 Alexios Zavras
dnl Copyright (C) 2022 Valasiadis Fotios
dnl SPDX-License-Identifier: LGPL-2.1-or-later

AC_INIT([Build Recorder], [1.0])

dnl Directories for auxiliary files and macros
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([
	1.12
	subdir-objects
	foreign
])

dnl Minimum autoconf version required
AC_PREREQ([2.69])

dnl Where to generate output
AC_CONFIG_HEADERS([src/config.h])


dnl Where are the sources
AC_CONFIG_SRCDIR([src/main.c])

AC_ARG_ENABLE([benchmarks],
	      [AS_HELP_STRING([--enable-benchmarks], [exclude benchmarks (default: disabled)])],
	      [enable_benchmarks=$enableval],
	      [enable_benchmarks=no])

AM_CONDITIONAL([ENABLE_BENCHMARKS], [test "x$enable_benchmarks" = "xyes"])

dnl Checks for programs
AC_CHECK_PROG(DOWNLOAD, curl, [curl -O])
if test "x$DOWNLOAD" = x; then
    AC_CHECK_PROG(DOWNLOAD, wget, wget)
fi
AM_CONDITIONAL([HAVE_DOWNLOAD], [test -n "$DOWNLOAD"])
AC_PATH_PROG(TIME, time)
AM_CONDITIONAL([HAVE_TIME], [test -n "$TIME"])
AC_CHECK_PROG(AWK, awk, [awk])
AM_CONDITIONAL([HAVE_AWK], [test -n "$AWK"])
AC_CHECK_PROG(XXD, xxd, [xxd])
AM_CONDITIONAL([HAVE_XXD], [test -n "$XXD"])


dnl Checks for libraries
AC_CHECK_LIB(crypto, EVP_sha1,, AC_MSG_ERROR([cannot find libcrypto]))

dnl Checks for headers
AC_CHECK_HEADER([errno.h],, AC_MSG_ERROR([cannot find errno.h]))
AC_CHECK_HEADER([error.h],, AC_MSG_ERROR([cannot find error.h]))
AC_CHECK_HEADER([fcntl.h],, AC_MSG_ERROR([cannot find fcntl.h]))
AC_CHECK_HEADER([limits.h],, AC_MSG_ERROR([cannot find limits.h]))
AC_CHECK_HEADER([linux/limits.h],, AC_MSG_ERROR([cannot find linux/limits.h]))
AC_CHECK_HEADER([linux/ptrace.h],, AC_MSG_ERROR([cannot find linux/ptrace.h]))
AC_CHECK_HEADER([openssl/evp.h],, AC_MSG_ERROR([cannot find openssl/evp.h]))
AC_CHECK_HEADER([stdbool.h],, AC_MSG_ERROR([cannot find stdbool.h]))
AC_CHECK_HEADER([stddef.h],, AC_MSG_ERROR([cannot find stddef.h]))
AC_CHECK_HEADER([stdint.h],, AC_MSG_ERROR([cannot find stdint.h]))
AC_CHECK_HEADER([stdio.h],, AC_MSG_ERROR([cannot find stdio.h]))
AC_CHECK_HEADER([stdlib.h],, AC_MSG_ERROR([cannot find stdlib.h]))
AC_CHECK_HEADER([string.h],, AC_MSG_ERROR([cannot find string.h]))
AC_CHECK_HEADER([sys/mman.h],, AC_MSG_ERROR([cannot find sys/mman.h]))
AC_CHECK_HEADER([sys/ptrace.h],, AC_MSG_ERROR([cannot find sys/ptrace.h]))
AC_CHECK_HEADER([sys/signal.h],, AC_MSG_ERROR([cannot find sys/signal.h]))
AC_CHECK_HEADER([sys/stat.h],, AC_MSG_ERROR([cannot find sys/stat.h]))
AC_CHECK_HEADER([sys/syscall.h],, AC_MSG_ERROR([cannot find sys/syscall.h]))
AC_CHECK_HEADER([sys/sysinfo.h],, AC_MSG_ERROR([cannot find sys/sysinfo.h]))
AC_CHECK_HEADER([sys/types.h],, AC_MSG_ERROR([cannot find sys/types.h]))
AC_CHECK_HEADER([sys/wait.h],, AC_MSG_ERROR([cannot find sys/wait.h]))
AC_CHECK_HEADER([sysexits.h],, AC_MSG_ERROR([cannot find sysexits.h]))
AC_CHECK_HEADER([time.h],, AC_MSG_ERROR([cannot find time.h]))
AC_CHECK_HEADER([unistd.h],, AC_MSG_ERROR([cannot find unistd.h]))

dnl Checks for typedefs and structures
AC_CHECK_TYPE([EVP_MD *],, AC_MSG_ERROR([cannot find EVP_MD *]), [#include <openssl/evp.h>])
AC_CHECK_TYPE([EVP_MD_CTX *],, AC_MSG_ERROR([cannot find EVP_MD_CTX *]), [#include <openssl/evp.h>])
AC_CHECK_TYPE([FILE *],, AC_MSG_ERROR([cannot find FILE *]), [#include <stdio.h>])
AC_CHECK_TYPE([pid_t],, AC_MSG_ERROR([cannot find pid_t]), [#include <sys/types.h>])
AC_CHECK_TYPE([ptrdiff_t],, AC_MSG_ERROR([cannot find ptrdiff_t]), [#include <stddef.h>])
AC_CHECK_TYPE([struct ptrace_syscall_info],, AC_MSG_ERROR([cannot find struct ptrace_syscall_info]), [#include <linux/ptrace.h>])
AC_CHECK_TYPE([time_t],, AC_MSG_ERROR([cannot find time_t]), [#include <time.h>])
AC_CHECK_TYPE([uint8_t],, AC_MSG_ERROR([cannot find uint8_t]), [#include <stdint.h>])


AC_CHECK_DECL([ARG_MAX],, AC_MSG_ERROR([cannot find ARG_MAX]), [#include <linux/limits.h>])
AC_CHECK_DECL([AT_FDCWD],, AC_MSG_ERROR([cannot find AT_FDCWD]), [#include <fcntl.h>])
AC_CHECK_DECL([ENOENT],, AC_MSG_ERROR([cannot find ENOENT]), [#include <errno.h>])
AC_CHECK_DECL([EXIT_FAILURE],, AC_MSG_ERROR([cannot find EXIT_FAILURE]), [#include <stdlib.h>])
AC_CHECK_DECL([EXIT_SUCCESS],, AC_MSG_ERROR([cannot find EXIT_SUCCESS]), [#include <stdlib.h>])
AC_CHECK_DECL([EX_USAGE],, AC_MSG_ERROR([cannot find EX_USAGE]), [#include <sysexits.h>])
AC_CHECK_DECL([MADV_SEQUENTIAL],, AC_MSG_ERROR([cannot find MADV_SEQUENTIAL]), [#include <sys/mman.h>])
AC_CHECK_DECL([MAP_FAILED],, AC_MSG_ERROR([cannot find MAP_FAILED]), [#include <sys/mman.h>])
AC_CHECK_DECL([MAP_PRIVATE],, AC_MSG_ERROR([cannot find MAP_PRIVATE]), [#include <sys/mman.h>])
AC_CHECK_DECL([NULL],, AC_MSG_ERROR([cannot find NULL]), [#include <stdlib.h>])
AC_CHECK_DECL([O_ACCMODE],, AC_MSG_ERROR([cannot find O_ACCMODE]), [#include <fcntl.h>])
AC_CHECK_DECL([O_RDONLY],, AC_MSG_ERROR([cannot find O_RDONLY]), [#include <fcntl.h>])
AC_CHECK_DECL([O_RDWR],, AC_MSG_ERROR([cannot find O_RDWR]), [#include <fcntl.h>])
AC_CHECK_DECL([O_WRONLY],, AC_MSG_ERROR([cannot find O_WRONLY]), [#include <fcntl.h>])
AC_CHECK_DECL([PATH_MAX],, AC_MSG_ERROR([cannot find PATH_MAX]), [#include <linux/limits.h>])
AC_CHECK_DECL([PTRACE_GET_SYSCALL_INFO],, AC_MSG_ERROR([cannot find PTRACE_GET_SYSCALL_INFO]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_EXITKILL],, AC_MSG_ERROR([cannot find PTRACE_O_EXITKILL]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_TRACECLONE],, AC_MSG_ERROR([cannot find PTRACE_O_TRACECLONE]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_TRACEFORK],, AC_MSG_ERROR([cannot find PTRACE_O_TRACEFORK]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_TRACESYSGOOD],, AC_MSG_ERROR([cannot find PTRACE_O_TRACESYSGOOD]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_TRACEVFORK],, AC_MSG_ERROR([cannot find PTRACE_O_TRACEVFORK]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_PEEKDATA],, AC_MSG_ERROR([cannot find PTRACE_PEEKDATA]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_SETOPTIONS],, AC_MSG_ERROR([cannot find PTRACE_SETOPTIONS]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_SYSCALL],, AC_MSG_ERROR([cannot find PTRACE_SYSCALL]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_SYSCALL_INFO_ENTRY],, AC_MSG_ERROR([cannot find PTRACE_SYSCALL_INFO_ENTRY]), [#include <linux/ptrace.h>])
AC_CHECK_DECL([PTRACE_SYSCALL_INFO_EXIT],, AC_MSG_ERROR([cannot find PTRACE_SYSCALL_INFO_EXIT]), [#include <linux/ptrace.h>])
AC_CHECK_DECL([PTRACE_TRACEME],, AC_MSG_ERROR([cannot find PTRACE_TRACEME]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([SIGSTOP],, AC_MSG_ERROR([cannot find SIGSTOP]), [#include <sys/signal.h>])
AC_CHECK_DECL([SIGTRAP],, AC_MSG_ERROR([cannot find SIGTRAP]), [#include <sys/signal.h>])
AC_CHECK_DECL([SYS_clone], [AC_DEFINE([HAVE_SYS_CLONE], [1], [[Define if SYS_clone is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_close], [AC_DEFINE([HAVE_SYS_CLOSE], [1], [[Define if SYS_close is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_creat], [AC_DEFINE([HAVE_SYS_CREAT], [1], [[Define if SYS_creat is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_execve], [AC_DEFINE([HAVE_SYS_EXECVE], [1], [[Define if SYS_execve is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_execveat], [AC_DEFINE([HAVE_SYS_EXECVEAT], [1], [[Define if SYS_execveat is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_fork], [AC_DEFINE([HAVE_SYS_FORK], [1], [[Define if SYS_fork is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_open], [AC_DEFINE([HAVE_SYS_OPEN], [1], [[Define if SYS_open is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_openat], [AC_DEFINE([HAVE_SYS_OPENAT], [1], [[Define if SYS_openat is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_rename], [AC_DEFINE([HAVE_SYS_RENAME], [1], [[Define if SYS_rename is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_renameat2], [AC_DEFINE([HAVE_SYS_RENAMEAT2], [1], [[Define if SYS_renameat2 is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_renameat], [AC_DEFINE([HAVE_SYS_RENAMEAT], [1], [[Define if SYS_renameat is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_vfork], [AC_DEFINE([HAVE_SYS_VFORK], [1], [[Define if SYS_vfork is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([S_ISLNK],, AC_MSG_ERROR([cannot find S_ISLNK]), [#include <sys/stat.h>])
AC_CHECK_DECL([S_ISREG],, AC_MSG_ERROR([cannot find S_ISREG]), [#include <sys/stat.h>])
AC_CHECK_DECL([WIFSTOPPED],, AC_MSG_ERROR([cannot find WIFSTOPPED]), [#include <wait.h>])
AC_CHECK_DECL([WSTOPSIG],, AC_MSG_ERROR([cannot find WSTOPSIG]), [#include <wait.h>])
AC_CHECK_DECL([errno],, AC_MSG_ERROR([cannot find errno]), [#include <errno.h>])


dnl Checks for functions
AC_CHECK_FUNC([EVP_DigestFinal_ex],, AC_MSG_ERROR([cannot find EVP_DigestFinal_ex(3)]))
AC_CHECK_FUNC([EVP_DigestInit_ex],, AC_MSG_ERROR([cannot find EVP_DigestInit_ex(3)]))
AC_CHECK_FUNC([EVP_DigestUpdate],, AC_MSG_ERROR([cannot find EVP_DigestUpdate(3)]))
AC_CHECK_FUNC([EVP_MD_CTX_free],, AC_MSG_ERROR([cannot find EVP_MD_CTX_free(3)]))
AC_CHECK_FUNC([EVP_MD_CTX_new],, AC_MSG_ERROR([cannot find EVP_MD_CTX_new(3)]))
AC_CHECK_FUNC([EVP_sha1],, AC_MSG_ERROR([cannot find EVP_sha1(3)]))
AC_CHECK_FUNC([calloc],, AC_MSG_ERROR([cannot find calloc(3)]))
AC_CHECK_FUNC([close],, AC_MSG_ERROR([cannot find close(2)]))
AC_CHECK_FUNC([error],, AC_MSG_ERROR([cannot find error(3)]))
AC_CHECK_FUNC([execvp],, AC_MSG_ERROR([cannot find execvp(2)]))
AC_CHECK_FUNC([fopen],, AC_MSG_ERROR([cannot find fopen(3)]))
AC_CHECK_FUNC([fork],, AC_MSG_ERROR([cannot find fork(2)]))
AC_CHECK_FUNC([fprintf],, AC_MSG_ERROR([cannot find fprintf(3)]))
AC_CHECK_FUNC([free],, AC_MSG_ERROR([cannot find free(3)]))
AC_CHECK_FUNC([fwrite],, AC_MSG_ERROR([cannot find fwrite(3)]))
AC_CHECK_FUNC([gmtime],, AC_MSG_ERROR([cannot find gmtime(3)]))
AC_CHECK_FUNC([madvise],, AC_MSG_ERROR([cannot find madvise(2)]))
AC_CHECK_FUNC([malloc],, AC_MSG_ERROR([cannot find malloc(3)]))
AC_CHECK_FUNC([mmap],, AC_MSG_ERROR([cannot find mmap(2)]))
AC_CHECK_FUNC([munmap],, AC_MSG_ERROR([cannot find munmap(2)]))
AC_CHECK_FUNC([open],, AC_MSG_ERROR([cannot find open(2)]))
AC_CHECK_FUNC([ptrace],, AC_MSG_ERROR([cannot find ptrace(2)]))
AC_CHECK_FUNC([read],, AC_MSG_ERROR([cannot find read(2)]))
AC_CHECK_FUNC([reallocarray],, AC_MSG_ERROR([cannot find reallocarray(3)]))
AC_CHECK_FUNC([realpath],, AC_MSG_ERROR([cannot find realpath(3)]))
AC_CHECK_FUNC([sprintf],, AC_MSG_ERROR([cannot find sprintf(3)]))
AC_CHECK_FUNC([stat],, AC_MSG_ERROR([cannot find stat(2)]))
AC_CHECK_FUNC([strcat],, AC_MSG_ERROR([cannot find strcat(3)]))
AC_CHECK_FUNC([strchr],, AC_MSG_ERROR([cannot find strchr(3)]))
AC_CHECK_FUNC([strcmp],, AC_MSG_ERROR([cannot find strcmp(3)]))
AC_CHECK_FUNC([strdup],, AC_MSG_ERROR([cannot find strdup(3)]))
AC_CHECK_FUNC([strftime],, AC_MSG_ERROR([cannot find strftime(3)]))
AC_CHECK_FUNC([time],, AC_MSG_ERROR([cannot find time(2)]))
AC_CHECK_FUNC([wait],, AC_MSG_ERROR([cannot find wait(2)]))
AC_CHECK_FUNC([waitpid],, AC_MSG_ERROR([cannot find waitpid(2)]))

dnl We need a C compiler
AC_PROG_CC

dnl Are we building from git checked-out sources, or a tarball?
AM_CONDITIONAL([BUILD_FROM_GIT], [test -d "$srcdir/.git"])

dnl What files to generate
AC_CONFIG_FILES([Makefile src/Makefile examples/Makefile benchmark/Makefile])

dnl Finally, generate everything
AC_OUTPUT

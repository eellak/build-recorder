
dnl Copyright (C) 2022 Alexios Zavras
dnl Copyright (C) 2022 Valasiadis Fotios
dnl SPDX-License-Identifier: LGPL-2.1-or-later

AC_INIT([Build Recorder], [0.1])

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
AC_CHECK_LIB(pthread, pthread_create,, AC_MSG_ERROR([cannot find libpthread]))

dnl Checks for headers
AC_CHECK_HEADER([linux/ptrace.h],, AC_MSG_ERROR([cannot find linux/ptrace.h]))
AC_CHECK_HEADER([openssl/evp.h],, AC_MSG_ERROR([cannot find openssl/evp.h]))
AC_CHECK_HEADER([sys/mman.h],, AC_MSG_ERROR([cannot find sys/mman.h]))
AC_CHECK_HEADER([sys/ptrace.h],, AC_MSG_ERROR([cannot find sys/ptrace.h]))
AC_CHECK_HEADER([sys/signal.h],, AC_MSG_ERROR([cannot find sys/signal.h]))
AC_CHECK_HEADER([sys/stat.h],, AC_MSG_ERROR([cannot find sys/stat.h]))
AC_CHECK_HEADER([sys/syscall.h],, AC_MSG_ERROR([cannot find sys/syscall.h]))
AC_CHECK_HEADER([sys/sysinfo.h],, AC_MSG_ERROR([cannot find sys/sysinfo.h]))
AC_CHECK_HEADER([sys/types.h],, AC_MSG_ERROR([cannot find sys/types.h]))
AC_CHECK_HEADER([sys/wait.h],, AC_MSG_ERROR([cannot find sys/wait.h]))
AC_CHECK_HEADER([sysexits.h],, AC_MSG_ERROR([cannot find sysexits.h]))
AC_CHECK_HEADER([pthread.h],, AC_MSG_ERROR([cannot find pthread.h]))

dnl Checks for typedefs and structures
AC_CHECK_TYPE([struct ptrace_syscall_info],, AC_MSG_ERROR([cannot find struct ptrace_syscall_info]), [#include <linux/ptrace.h>])

AC_CHECK_TYPE([pid_t],, AC_MSG_ERROR([cannot find pid_t]), [#include <sys/types.h>])

AC_CHECK_TYPE([pthread_t],, AC_MSG_ERROR([cannot find pthread_t]), [#include <pthread.h>])
AC_CHECK_TYPE([pthread_mutex_t],, AC_MSG_ERROR([cannot find pthread_mutex_t]), [#include <pthread.h>])
AC_CHECK_TYPE([pthread_cond_t],, AC_MSG_ERROR([cannot find pthread_cond_t]), [#include <pthread.h>])

AC_CHECK_DECL([PATH_MAX],, AC_MSG_ERROR([cannot find PATH_MAX]), [#include <linux/limits.h>])
AC_CHECK_DECL([ARG_MAX],, AC_MSG_ERROR([cannot find ARG_MAX]), [#include <linux/limits.h>])

AC_CHECK_DECL([PTRACE_GET_SYSCALL_INFO],, AC_MSG_ERROR([cannot find PTRACE_GET_SYSCALL_INFO]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_SYSCALL],, AC_MSG_ERROR([cannot find PTRACE_SYSCALL]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_PEEKDATA],, AC_MSG_ERROR([cannot find PTRACE_PEEKDATA]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_SETOPTIONS],, AC_MSG_ERROR([cannot find PTRACE_SETOPTIONS]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_EXITKILL],, AC_MSG_ERROR([cannot find PTRACE_O_EXITKILL]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_TRACESYSGOOD],, AC_MSG_ERROR([cannot find PTRACE_O_TRACESYSGOOD]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_TRACECLONE],, AC_MSG_ERROR([cannot find PTRACE_O_TRACECLONE]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_TRACEFORK],, AC_MSG_ERROR([cannot find PTRACE_O_TRACEFORK]), [#include <sys/ptrace.h>])
AC_CHECK_DECL([PTRACE_O_TRACEVFORK],, AC_MSG_ERROR([cannot find PTRACE_O_TRACEVFORK]), [#include <sys/ptrace.h>])

AC_CHECK_DECL([PTRACE_SYSCALL_INFO_ENTRY],, AC_MSG_ERROR([cannot find PTRACE_SYSCALL_INFO_ENTRY]), [#include <linux/ptrace.h>])
AC_CHECK_DECL([PTRACE_SYSCALL_INFO_EXIT],, AC_MSG_ERROR([cannot find PTRACE_SYSCALL_INFO_EXIT]), [#include <linux/ptrace.h>])

AC_CHECK_DECL([SIGTRAP],, AC_MSG_ERROR([cannot find SIGTRAP]), [#include <sys/signal.h>])
AC_CHECK_DECL([SIGSTOP],, AC_MSG_ERROR([cannot find SIGSTOP]), [#include <sys/signal.h>])

AC_CHECK_DECL([SYS_clone], [AC_DEFINE([HAVE_SYS_CLONE], [1], [[Define if SYS_clone is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_close], [AC_DEFINE([HAVE_SYS_CLOSE], [1], [[Define if SYS_close is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_creat], [AC_DEFINE([HAVE_SYS_CREAT], [1], [[Define if SYS_creat is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_execve], [AC_DEFINE([HAVE_SYS_EXECVE], [1], [[Define if SYS_execve is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_execveat], [AC_DEFINE([HAVE_SYS_EXECVEAT], [1], [[Define if SYS_execveat is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_fork], [AC_DEFINE([HAVE_SYS_FORK], [1], [[Define if SYS_fork is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_open], [AC_DEFINE([HAVE_SYS_OPEN], [1], [[Define if SYS_open is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_openat], [AC_DEFINE([HAVE_SYS_OPENAT], [1], [[Define if SYS_openat is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_rename], [AC_DEFINE([HAVE_SYS_RENAME], [1], [[Define if SYS_rename is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_renameat], [AC_DEFINE([HAVE_SYS_RENAMEAT], [1], [[Define if SYS_renameat is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_renameat2], [AC_DEFINE([HAVE_SYS_RENAMEAT2], [1], [[Define if SYS_renameat2 is available]])],, [#include <sys/syscall.h>])
AC_CHECK_DECL([SYS_vfork], [AC_DEFINE([HAVE_SYS_VFORK], [1], [[Define if SYS_vfork is available]])],, [#include <sys/syscall.h>])

AC_CHECK_DECL([MADV_SEQUENTIAL],, AC_MSG_ERROR([cannot find MADV_SEQUENTIAL]), [#include <sys/mman.h>])

dnl Checks for functions
AC_CHECK_FUNC([fork],, AC_MSG_ERROR([cannot find fork(2)]))
AC_CHECK_FUNC([ptrace],, AC_MSG_ERROR([cannot find ptrace(2)]))
AC_CHECK_FUNC([waitpid],, AC_MSG_ERROR([cannot find waitpid(2)]))

AC_CHECK_FUNC([mmap],, AC_MSG_ERROR([cannot find mmap(2)]))
AC_CHECK_FUNC([madvise],, AC_MSG_ERROR([cannot find madvise(2)]))

AC_CHECK_FUNC([EVP_DigestInit_ex],, AC_MSG_ERROR([cannot find EVP_DigestInit_ex(3)]))
AC_CHECK_FUNC([EVP_DigestUpdate],, AC_MSG_ERROR([cannot find EVP_DigestUpdate(3)]))
AC_CHECK_FUNC([EVP_DigestFinal_ex],, AC_MSG_ERROR([cannot find EVP_DigestFinal_ex(3)]))

AC_CHECK_FUNC([pthread_mutex_lock],, AC_MSG_ERROR([cannot find pthread_mutex_lock(3)]))
AC_CHECK_FUNC([pthread_cond_wait],, AC_MSG_ERROR([cannot find pthread_cond_wait(3)]))
AC_CHECK_FUNC([pthread_mutex_unlock],, AC_MSG_ERROR([cannot find pthread_mutex_unlock(3)]))
AC_CHECK_FUNC([pthread_mutex_init],, AC_MSG_ERROR([cannot find pthread_mutex_init(3)]))
AC_CHECK_FUNC([pthread_cond_init],, AC_MSG_ERROR([cannot find pthread_cond_init(3)]))
AC_CHECK_FUNC([pthread_create],, AC_MSG_ERROR([cannot find pthread_create(3)]))
AC_CHECK_FUNC([pthread_cond_signal],, AC_MSG_ERROR([cannot find pthread_cond_signal(3)]))
AC_CHECK_FUNC([pthread_cond_broadcast],, AC_MSG_ERROR([cannot find pthread_cond_broadcast(3)]))
AC_CHECK_FUNC([pthread_join],, AC_MSG_ERROR([cannot find pthread_join(3)]))
AC_CHECK_FUNC([pthread_mutex_destroy],, AC_MSG_ERROR([cannot find pthread_mutex_destroy(3)]))
AC_CHECK_FUNC([pthread_cond_destroy],, AC_MSG_ERROR([cannot find pthread_cond_destroy(3)]))

dnl We need a C compiler
AC_PROG_CC

dnl Are we building from git checked-out sources, or a tarball?
AM_CONDITIONAL([BUILD_FROM_GIT], [test -d "$srcdir/.git"])

dnl What files to generate
AC_CONFIG_FILES([Makefile src/Makefile examples/Makefile benchmark/Makefile])

dnl Finally, generate everything
AC_OUTPUT

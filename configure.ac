
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
AC_CONFIG_HEADERS([config.h])


dnl Where are the sources
AC_CONFIG_SRCDIR([src/main.c])

dnl Checks for programs
dnl Checks for libraries
AC_CHECK_LIB(crypto, SHA1_Init)

dnl Checks for headers
AC_CHECK_HEADERS([
	sys/ptrace.h
	linux/ptrace.h
	sys/signal.h
	sys/syscall.h
	sys/wait.h
])

AC_CHECK_HEADERS([
	sysexits.h
	sys/mman.h
	sys/stat.h
	sys/sysinfo.h
	sys/types.h
	openssl/sha.h
])

dnl Checks for typedefs and structures
AC_CHECK_TYPES(m4_normalize([
	pid_t,
	struct ptrace_syscall_info
]),,, [#include <linux/ptrace.h>])

AC_CHECK_TYPE([SHA_CTX],,, [#include <openssl/sha.h>])

AC_CHECK_TYPE([PATH_MAX],,, [#include <limits.h>])

AC_CHECK_DECLS(m4_normalize([
	PTRACE_GET_SYSCALL_INFO,
	PTRACE_SYSCALL,
	PTRACE_PEEKDATA,
	PTRACE_SETOPTIONS,
	PTRACE_O_EXITKILL,
	PTRACE_O_TRACESYSGOOD,
	PTRACE_O_TRACECLONE,
	PTRACE_O_TRACEFORK,
	PTRACE_O_TRACEVFORK
]),,, [#include <sys/ptrace.h>])

AC_CHECK_DECLS(m4_normalize([
	PTRACE_SYSCALL_INFO_ENTRY,
	PTRACE_SYSCALL_INFO_EXIT
]),,, [#include <linux/ptrace.h>])

AC_CHECK_DECLS(m4_normalize([
	SIGTRAP,
	SIGSTOP
]),,, [#include <sys/signal.h>])

AC_CHECK_DECLS(m4_normalize([
	SYS_open,
	SYS_creat,
	SYS_openat,
	SYS_close
]),,, [#include <sys/syscall.h>])

AC_CHECK_DECL([MADV_SEQUENTIAL],,, [#include <sys/mman.h>])

dnl Checks for functions
AC_CHECK_FUNCS([SHA1_Init SHA1_Update SHA1_Final])
AC_CHECK_FUNCS([fork ptrace waitpid wait])
AC_CHECK_FUNCS([mmap madvise])

dnl We need a C compiler
AC_PROG_CC

dnl Are we building from git checked-out sources, or a tarball?
AM_CONDITIONAL([BUILD_FROM_GIT], [test -d "$srcdir/.git"])

dnl What files to generate
AC_CONFIG_FILES([Makefile])

dnl Finally, generate everything
AC_OUTPUT

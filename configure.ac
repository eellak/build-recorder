
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
AC_CHECK_LIB(crypto, EVP_DigestInit_ex)

dnl Checks for headers
AC_CHECK_HEADERS([m4_normalize([
	linux/ptrace.h
	openssl/evp.h
	sys/mman.h
	sys/ptrace.h
	sys/signal.h
	sys/stat.h
	sys/syscall.h
	sys/sysinfo.h
	sys/types.h
	sys/wait.h
	sysexits.h
])])

dnl Checks for typedefs and structures
AC_CHECK_TYPES(m4_normalize([
	struct ptrace_syscall_info
]),,, [#include <linux/ptrace.h>])

AC_CHECK_TYPES(m4_normalize([
	pid_t
]),,, [#include <sys/types.h>])

AC_CHECK_TYPES(m4_normalize([
	EVP_MD_CTX *,
	EVP_MD *
]),,, [#include <openssl/evp.h>])

AC_CHECK_DECL([PATH_MAX],,, [#include <limits.h>])

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
AC_CHECK_FUNCS(m4_normalize([
	EVP_get_digestbyname
	EVP_MD_CTX_new
	EVP_MD_CTX_free
	EVP_DigestInit_ex
	EVP_DigestUpdate
	EVP_DigestFinal_ex
]))
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

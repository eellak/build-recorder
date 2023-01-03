
/*
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "config.h"

#include <errno.h>		       // errno(3)
#include <error.h>		       // error(3)
#include <fcntl.h>		       // open(2)
#include <limits.h>		       // PATH_MAX
#include <stdint.h>		       // uint8_t
#include <stdio.h>		       // sprintf(3)
#include <stdlib.h>		       // realpath(3), exit(3), atoi(3)
#include <string.h>		       // memcmp(3), strcmp(3), strdup(3),
				       // strlen(3)
#include <sysexits.h>		       // EX_OK, EX_NOINPUT, EX_USAGE
#include <sys/mman.h>		       // madvise(2), mmap(2)
#include <sys/stat.h>		       // lstat(2)
#include <sys/sysinfo.h>	       // get_nprocs(3)
#include <sys/types.h>		       // 
#include <unistd.h>		       // optind, readlink(2)

#include <openssl/sha.h>	       // SHA_CTX, SHA1_Init, SHA1_Update,
				       // SHA1_Final

#define	ZERO_FILE_HASH	"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

#include	"hash.h"

static char *
hash_to_str(uint8_t *h)
{
    char *hash;
    char *ph;

    ph = hash = malloc(SHA1_HEXBUF_LEN);
    if (hash == NULL) {
	return NULL;
    }

    for (int i = 0; i < SHA1_OUTPUT_LEN; i++) {
#define TO_HEX(i)       "0123456789abcdef"[i]
	*ph++ = TO_HEX(h[i] >> 4);
	*ph++ = TO_HEX(h[i] & 0xF);
    }
    *ph = 0;
    return hash;
}

static uint8_t *
hash_file_contents(char *name, size_t sz)
{
    int fd = open(name, O_RDONLY);

    if (fd < 0) {
	error(0, errno, "open `%s'", name);
	return NULL;
    }
    char *buf = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);

    if (buf == MAP_FAILED) {
	error(0, errno, "mmaping `%s'", name);
	return NULL;
    }
    int ret = madvise(buf, sz, MADV_SEQUENTIAL);

    if (ret) {
	error(0, errno, "madvise `%s'", name);
    }

    char pre[32];
    size_t presize;

    presize = sprintf(pre, "blob %lu%c", sz, 0);

    SHA_CTX ctx;
    unsigned char *hash;

    hash = malloc(SHA1_OUTPUT_LEN);
    if (hash == NULL) {
	error(0, errno, "malloc output on `%s'", name);
	return NULL;
    }

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, pre, presize);
    SHA1_Update(&ctx, buf, sz);
    SHA1_Final(hash, &ctx);

    close(fd);

    if (munmap(buf, sz) < 0) {
	error(EXIT_FAILURE, errno, "unmapping `%s'", name);
    }

    return hash;
}

char *
get_file_hash(char *fname)
{
    struct stat fstat;

    if (stat(fname, &fstat)) {
	error(0, errno, "getting info on `%s'", fname);
	return NULL;
    }
    if (S_ISREG(fstat.st_mode) || S_ISLNK(fstat.st_mode)) {
	size_t sz = fstat.st_size;

	if (sz > 0) {
	    uint8_t *h = hash_file_contents(fname, sz);
	    char *ret = hash_to_str(h);

	    free(h);
	    return ret;
	} else {
	    return strdup(ZERO_FILE_HASH);
	}
    } else {
	return NULL;
    }
}

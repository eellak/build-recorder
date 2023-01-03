
/*
Copyright (C) 2022 Valasiadis Fotios
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	<stdlib.h>
#include	<string.h>
#include	<error.h>
#include	<errno.h>
#include	"hashmap.h"

#define DEFAULT_CAPACITY 32

int
hash_str(char *str)
{
    int hash = 7;

    while (*str) {
	hash = hash * 31 + *str;
	++str;
    }

    return hash;
}

static void
 hashmap_reallocate(hashmap *self);

static void
hashmap_new_impl(hashmap *self, int capacity)
{
    self->keys = calloc(capacity, sizeof (key_type));
    self->values = calloc(capacity, sizeof (value_type));

    if (!self->keys || !self->values)
	error(EXIT_FAILURE, errno, "on hashmap_new");

    self->capacity = capacity;
    self->size = 0;
}

void
hashmap_new(hashmap *self)
{
    hashmap_new_impl(self, DEFAULT_CAPACITY);
}

value_type *
hashmap_insert(hashmap *self, key_type key)
{
    if (self->size == self->capacity) {
	hashmap_reallocate(self);
    }

    int pos = hash_str(key) & (self->capacity - 1);

    while (pos != self->capacity && self->keys[pos]
	   && strcmp(self->keys[pos], key)) {
	++pos;
    }

    if (pos == self->capacity) {
	pos = 0;
	while (self->keys[pos] && strcmp(self->keys[pos], key)) {
	    ++pos;
	}
    }

    if (!self->keys[pos]) {
	self->keys[pos] = key;
	++self->size;
    }

    return self->values + pos;
}

static void
hashmap_free(hashmap *self)
{
    free(self->keys);
    free(self->values);
}

static void
hashmap_reallocate(hashmap *self)
{
    hashmap hm;

    hashmap_new_impl(&hm, self->capacity * 2);

    for (int i = 0; i < self->capacity; ++i) {
	if (!self->keys[i])
	    continue;

	*hashmap_insert(&hm, self->keys[i]) = self->values[i];
    }

    hashmap_free(self);
    *self = hm;
}

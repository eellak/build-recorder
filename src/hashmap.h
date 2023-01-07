
/*
Copyright (C) 2022 Valasiadis Fotios
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "types.h"

/* Simple hashmap with open addressing linear probing. */

typedef char *key_type;
typedef FILE_INFO value_type;

typedef struct {
    key_type *keys;
    value_type *values;
    int size;
    int capacity;
} hashmap;

void hashmap_new(hashmap *self);

value_type *hashmap_insert(hashmap *self, key_type key);

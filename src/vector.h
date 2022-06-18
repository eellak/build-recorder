/*
	Copyright (C) 2022 Valasiadis Fotios
	SPDX-License-Identifier: LGPL-2.1-or-later
*/

#ifndef value_type
#define value_type int
#endif

#ifndef vector_name
#define vector_name vector
#endif

// Prior to including this header, define "vector_name" and "value type".

#define _method(name, m) name##_##m
#define method(m) _method(vector_name, m)

#include <stdlib.h>

struct vector_name {
    value_type *arr;
    size_t size;
    size_t capacity;
};

static inline void 
method(new)(struct vector_name *self) {
    self->arr = NULL;
    self->size = 0;
    self->capacity = 0;
}

static inline void 
method(free)(struct vector_name *self)
{
    if(self->capacity) {
        free(self->arr);
        self->capacity = 0;
        self->size = 0;
    }
}

static inline void
method(reserve)(struct vector_name *self, size_t capacity)
{
    if(capacity && !self->capacity) {
        self->capacity = 1;
    }

    if(self->capacity < capacity) {
        while(self->capacity < capacity) {
            self->capacity *= 2;
        }

        self->arr = (value_type *)realloc(self->arr, capacity * sizeof(value_type));
    }
}

static inline void
method(extend)(struct vector_name *self)
{
    method(reserve)(self, self->capacity * 2);
}

static inline void
method(push_back)(struct vector_name *self, value_type *value)
{
    if(self->size == self->capacity) {
        method(extend)(self);
    }

    self->arr[self->size] = *value;
    ++self->size;
}

#undef _method
#undef method
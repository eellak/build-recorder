/*
	Copyright (C) 2022-current Valasiadis Fotios

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
    USA
*/

#ifndef value_type
#define value_type int
#endif

#ifndef vector_name
#define vector_name vector
#endif

#include <stdlib.h>

// Prior to including this header, define "vector_name" and "value type".

#define _method(name, m) name##_##m
#define method(m) _method(vector_name, m)

struct vector_name {
    value_type *arr;
    size_t size;
    size_t capacity;
};

void 
method(new)(struct vector_name *self) {
    self->arr = NULL;
    self->size = 0;
    self->capacity = 0;
}

void 
method(free)(struct vector_name *self)
{
    if(self->capacity) {
        free(self->arr);
        self->capacity = 0;
        self->size = 0;
    }
}

void
method(reserve)(struct vector_name *self, size_t capacity)
{
    if(self->capacity < capacity) {
        while(self->capacity < capacity) {
            self->capacity *= 2;
        }

        self->arr = (value_type *)realloc(self->arr, capacity * sizeof(value_type));
    }
}

void
method(extend)(struct vector_name *self)
{
    method(reserve)(self, self->capacity * 2);
}

void
method(push_back)(struct vector_name *self, value_type *value)
{
    if(self->size == self->capacity) {
        method(extend);
    }

    self->arr[self->size] = *value;
    ++self->size;
}

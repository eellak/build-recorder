
/*
Copyright (C) 2022 Valasiadis Fotios
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	<pthread.h>

typedef struct {
    void (*fun)(void *);
    void *arg;
} packaged_task;

typedef struct {
    pthread_t *workers;
    int workers_size;

    packaged_task *tasks;
    int numtasks;
    int tasks_size;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    char stop;
} threadpool;

void threadpool_new(threadpool *self, int workers_size);

void threadpool_enqueue(threadpool *self, packaged_task task);

void threadpool_destroy(threadpool *self);

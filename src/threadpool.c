
/*
Copyright (C) 2022 Valasiadis Fotios
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include	<stdlib.h>
#include	<error.h>
#include	<errno.h>
#include	"threadpool.h"
#include <stdio.h>

static void *
worker(void *arg)
{
    threadpool *pool = (threadpool *) arg;

    while (1) {
	pthread_mutex_lock(&pool->lock);
	while (!pool->stop && pool->numtasks == -1) {
	    pthread_cond_wait(&pool->cond, &pool->lock);
	}
	if (pool->stop && pool->numtasks == -1) {
	    pthread_mutex_unlock(&pool->lock);
	    return NULL;
	}
	packaged_task task = pool->tasks[pool->numtasks--];

	pthread_mutex_unlock(&pool->lock);

	task.fun(task.arg);
    }
}

void
threadpool_new(threadpool *self, int workers_size)
{
    pthread_mutex_init(&self->lock, NULL);
    pthread_cond_init(&self->cond, NULL);

    self->workers = malloc(workers_size * sizeof (pthread_t));
    self->workers_size = workers_size;
    self->stop = 0;

    self->tasks_size = 256;
    self->tasks = malloc(self->tasks_size * sizeof (packaged_task));
    self->numtasks = -1;

    while (workers_size--) {
	if (pthread_create(self->workers + workers_size, NULL, worker, self) <
	    0) {
	    error(EXIT_FAILURE, errno, "on threadpool_new pthread_create");
	}
    }
}

void
threadpool_enqueue(threadpool *self, packaged_task task)
{
    pthread_mutex_lock(&self->lock);
    self->tasks[++self->numtasks] = task;
    pthread_mutex_unlock(&self->lock);

    pthread_cond_signal(&self->cond);
}

void
threadpool_destroy(threadpool *self)
{
    pthread_mutex_lock(&self->lock);
    self->stop = 1;
    pthread_mutex_unlock(&self->lock);

    pthread_cond_broadcast(&self->cond);
    while (self->workers_size--) {
	pthread_join(self->workers[self->workers_size], NULL);
    }

    pthread_mutex_destroy(&self->lock);
    pthread_cond_destroy(&self->cond);
}

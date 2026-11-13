/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "ot_iovec.h"
#include "ot_workqueue.h"
#include "trackerlogic.h"

extern int g_self_pipe[2];

struct ot_task {
  struct catalog_query query;
  ot_taskid taskid;
  ot_tasktype tasktype;
  int64_t sock;
  size_t iovec_entries;
  struct iovec *iovec;
  struct ot_task *next;
};

static ot_taskid next_free_taskid = 1;
static struct ot_task *tasklist;
static pthread_mutex_t tasklist_mutex;
static pthread_cond_t tasklist_being_filled;

int workqueue_pushtask(int64_t sock, ot_tasktype tasktype) { return workqueue_pushquery(sock, tasktype, NULL); }

int workqueue_pushquery(int64_t sock, ot_tasktype tasktype, const struct catalog_query *query) {
  struct ot_task **tmptask, *task;

  task = malloc(sizeof(struct ot_task));
  if (!task)
    return -1;

  task->query = query ? *query : (struct catalog_query){0};
  task->taskid = 0;
  task->tasktype = tasktype;
  task->sock = sock;
  task->iovec_entries = 0;
  task->iovec = NULL;
  task->next = 0;

  pthread_mutex_lock(&tasklist_mutex);

  tmptask = &tasklist;
  while (*tmptask)
    tmptask = &(*tmptask)->next;
  *tmptask = task;

  pthread_cond_broadcast(&tasklist_being_filled);
  pthread_mutex_unlock(&tasklist_mutex);
  return 0;
}

void workqueue_canceltask(int64_t sock) {
  struct ot_task **task;

  pthread_mutex_lock(&tasklist_mutex);

  for (task = &tasklist; *task; task = &((*task)->next))
    if ((*task)->sock == sock) {
      struct iovec *iovec = (*task)->iovec;
      struct ot_task *ptask = *task;
      size_t i;

      for (i = 0; i < (*task)->iovec_entries; ++i)
        free(iovec[i].iov_base);
      free(iovec);

      *task = (*task)->next;
      free(ptask);
      break;
    }

  pthread_mutex_unlock(&tasklist_mutex);
}

ot_taskid workqueue_poptask(ot_tasktype *tasktype) { return workqueue_popquery(tasktype, NULL); }

ot_taskid workqueue_popquery(ot_tasktype *tasktype, struct catalog_query *query) {
  struct ot_task *task;
  ot_taskid taskid = 0;

  pthread_mutex_lock(&tasklist_mutex);

  while (!taskid) {

    for (task = tasklist; task; task = task->next)
      if (!task->taskid && (TASK_CLASS_MASK & task->tasktype) == *tasktype) {

        task->taskid = taskid = ++next_free_taskid;
        *tasktype = task->tasktype;
        if (query)
          *query = task->query;
        break;
      }

    if (!taskid) {
      if (!tracker_running)
        break;
      pthread_cond_wait(&tasklist_being_filled, &tasklist_mutex);
    }
  }

  pthread_mutex_unlock(&tasklist_mutex);

  return taskid;
}

void workqueue_pushsuccess(ot_taskid taskid) {
  struct ot_task **task;

  pthread_mutex_lock(&tasklist_mutex);

  for (task = &tasklist; *task; task = &((*task)->next))
    if ((*task)->taskid == taskid) {
      struct ot_task *ptask = *task;
      *task = (*task)->next;
      free(ptask);
      break;
    }

  pthread_mutex_unlock(&tasklist_mutex);
}

int workqueue_pushresult(ot_taskid taskid, size_t iovec_entries, struct iovec *iovec) {
  struct ot_task *task;
  const char byte = 'o';

  pthread_mutex_lock(&tasklist_mutex);

  for (task = tasklist; task; task = task->next)
    if (task->taskid == taskid) {
      task->iovec_entries = iovec_entries;
      task->iovec = iovec;
      task->tasktype = TASK_DONE;
      break;
    }

  pthread_mutex_unlock(&tasklist_mutex);

  (void)!write(g_self_pipe[1], &byte, 1);

  return task ? 0 : -1;
}

int workqueue_pushchunked(ot_taskid taskid, struct iovec *iovec) {
  struct ot_task *task;
  const char byte = 'o';

  pthread_mutex_lock(&tasklist_mutex);

  for (task = tasklist; task; task = task->next)
    if (task->taskid == taskid) {
      if (iovec) {
        if (iovec_append(&task->iovec_entries, &task->iovec, iovec))
          task->tasktype = TASK_DONE_PARTIAL;
        else
          task = NULL;
      } else
        task->tasktype = TASK_DONE;
      break;
    }

  pthread_mutex_unlock(&tasklist_mutex);

  (void)!write(g_self_pipe[1], &byte, 1);

  return task ? 0 : -1;
}

int64_t workqueue_popresult(size_t *iovec_entries, struct iovec **iovec, int *is_partial) {
  struct ot_task **task;
  int64_t sock = -1;

  *is_partial = 0;

  pthread_mutex_lock(&tasklist_mutex);

  for (task = &tasklist; *task; task = &((*task)->next))
    if (((*task)->tasktype & TASK_CLASS_MASK) == TASK_DONE) {
      struct ot_task *ptask = *task;
      *iovec_entries = ptask->iovec_entries;
      *iovec = ptask->iovec;
      sock = ptask->sock;

      if ((*task)->tasktype == TASK_DONE) {
        *task = ptask->next;
        free(ptask);
      } else {
        ptask->iovec_entries = 0;
        ptask->iovec = NULL;
        *is_partial = 1;

        (*task)->tasktype = TASK_FULLSCRAPE;
      }
      break;
    }

  pthread_mutex_unlock(&tasklist_mutex);
  return sock;
}

void workqueue_wakeall(void) {
  pthread_mutex_lock(&tasklist_mutex);
  pthread_cond_broadcast(&tasklist_being_filled);
  pthread_mutex_unlock(&tasklist_mutex);
}

void workqueue_init(void) {
  pthread_mutex_init(&tasklist_mutex, NULL);
  pthread_cond_init(&tasklist_being_filled, NULL);
}

void workqueue_deinit(void) {
  pthread_mutex_destroy(&tasklist_mutex);
  pthread_cond_destroy(&tasklist_being_filled);
}

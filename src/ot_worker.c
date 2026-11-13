/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ot_worker.h"
#include "trackerlogic.h"

static struct ot_worker **g_workers;
static size_t g_worker_count;

static void *worker_trampoline(void *args) {
  struct ot_worker *me = args;

  if (workstruct_init(&me->ws, G_INBUF_SIZE) == -1)
    fprintf(stderr, "Warning: a worker could not get its buffers and will not run.\n");
  else {
    me->run(me);
    workstruct_deinit(&me->ws);
  }

  atomic_store(&me->left, 1);
  return NULL;
}

int worker_start(ot_worker_run run, int64_t sock) {
  struct ot_worker **grown = realloc(g_workers, (g_worker_count + 1) * sizeof(*g_workers));
  struct ot_worker *worker;

  if (!grown)
    return -1;
  g_workers = grown;

  if (!(worker = calloc(1, sizeof(*worker))))
    return -1;
  worker->sock = sock;
  worker->run = run;

  if (pthread_create(&worker->thread, NULL, worker_trampoline, worker)) {
    free(worker);
    return -1;
  }
  g_workers[g_worker_count++] = worker;
  return 0;
}

void worker_stop_all(void) {
  size_t i;

  for (i = 0; i < g_worker_count; ++i) {
    struct ot_worker *worker = g_workers[i];

    while (!atomic_load(&worker->left)) {
      pthread_kill(worker->thread, OT_SIGNAL_WAKE);
      usleep(1000);
    }
    pthread_join(worker->thread, NULL);
    free(worker);
  }

  free(g_workers);
  g_workers = NULL;
  g_worker_count = 0;
}

/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_WORKER_H__
#define OT_WORKER_H__

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#include "trackerlogic.h"

struct ot_worker;

typedef void (*ot_worker_run)(struct ot_worker *worker);

struct ot_worker {
  pthread_t thread;
  _Atomic int left;
  int64_t sock;
  ot_worker_run run;
  struct ot_workstruct ws;
};

int worker_start(ot_worker_run run, int64_t sock);

void worker_stop_all(void);

#endif

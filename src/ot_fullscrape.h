/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_FULLSCRAPE_H__
#define OT_FULLSCRAPE_H__

#ifdef WANT_FULLSCRAPE

#include "ot_mutex.h"
#include "ot_workqueue.h"

void fullscrape_init(void);
void fullscrape_deinit(void);
void fullscrape_deliver(int64_t sock, ot_tasktype tasktype);

#else

#define fullscrape_init()
#define fullscrape_deinit()

#endif

#endif

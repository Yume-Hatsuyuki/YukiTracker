/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_CLEAN_H__
#define OT_CLEAN_H__

#include "trackerlogic.h"

#define OT_CLEAN_INTERVAL_MINUTES 2

#define OT_CLEAN_MAX_WAKES_PER_SECOND 10

#define OT_CLEAN_WAKE_BUDGET ((OT_CLEAN_INTERVAL_MINUTES) * 60 * (OT_CLEAN_MAX_WAKES_PER_SECOND))
#define OT_CLEAN_BUCKETS_PER_WAKE (((OT_BUCKET_COUNT) + (OT_CLEAN_WAKE_BUDGET) - 1) / (OT_CLEAN_WAKE_BUDGET))
#define OT_CLEAN_WAKES ((OT_BUCKET_COUNT) / (OT_CLEAN_BUCKETS_PER_WAKE))
#define OT_CLEAN_SLEEP (((OT_CLEAN_INTERVAL_MINUTES) * 60 * 1000000) / (OT_CLEAN_WAKES))

void clean_init(void);
void clean_deinit(void);
int clean_single_torrent(ot_torrent *torrent);

#endif

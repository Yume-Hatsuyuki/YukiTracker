/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_MUTEX_H__
#define OT_MUTEX_H__

#include <sys/uio.h>
#include "trackerlogic.h"

void mutex_init(void);
void mutex_deinit(void);

ot_vector *mutex_bucket_lock(int bucket);
ot_vector *mutex_bucket_lock_by_hash(ot_hash const hash);

void mutex_bucket_unlock(int bucket, int delta_torrentcount);
void mutex_bucket_unlock_by_hash(ot_hash const hash, int delta_torrentcount);

typedef struct {
  size_t torrents, ipv4, ipv6, seeders;
  unsigned long long completed;
} ot_swarm_counts;

void mutex_bucket_invalidate(int bucket);
void mutex_swarm_counts(ot_swarm_counts *total);

size_t mutex_get_torrent_count(void);

#endif

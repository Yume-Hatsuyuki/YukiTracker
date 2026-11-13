/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>

#include "ot_iovec.h"
#include "ot_mutex.h"
#include "ot_stats.h"
#include "trackerlogic.h"

#define MTX_DBG(STRING)

static ot_vector all_torrents[OT_BUCKET_COUNT];
static pthread_mutex_t bucket_mutex[OT_BUCKET_COUNT];

static _Atomic size_t g_torrent_count;
static struct {
  ot_swarm_counts counts;
  int valid;
} summaries[OT_BUCKET_COUNT];

void mutex_bucket_invalidate(int bucket) { summaries[bucket].valid = 0; }

void mutex_swarm_counts(ot_swarm_counts *total) {
  *total = (ot_swarm_counts){0};
  for (int bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket) {
    ot_vector *list = mutex_bucket_lock(bucket);
    ot_swarm_counts *counts = &summaries[bucket].counts;
    if (!summaries[bucket].valid) {
      *counts = (ot_swarm_counts){.torrents = list->size};
      const ot_torrent *rows = list->data;
      for (size_t i = 0; i < list->size; ++i) {
        const ot_peerlist *peers = rows[i].peer_list;
        counts->completed += rows[i].down_count;
        if (peers) {
          counts->ipv4 += vector_peer_count(&peers->peers4);
          counts->ipv6 += vector_peer_count(&peers->peers6);
          counts->seeders += peers->seed_count;
        }
      }
      summaries[bucket].valid = 1;
    }
    ot_swarm_counts copy = *counts;
    mutex_bucket_unlock(bucket, 0);
    total->torrents += copy.torrents;
    total->ipv4 += copy.ipv4;
    total->ipv6 += copy.ipv6;
    total->seeders += copy.seeders;
    total->completed += copy.completed;
  }
}

ot_vector *mutex_bucket_lock(int bucket) {
  pthread_mutex_lock(bucket_mutex + bucket);
  return all_torrents + bucket;
}

static int bucket_from_hash(ot_hash const hash) {
  uint32_t bucket;
  memcpy(&bucket, hash, sizeof(bucket));
  return ntohl(bucket) >> OT_BUCKET_COUNT_SHIFT;
}

ot_vector *mutex_bucket_lock_by_hash(ot_hash const hash) { return mutex_bucket_lock(bucket_from_hash(hash)); }

void mutex_bucket_unlock(int bucket, int delta_torrentcount) {
  pthread_mutex_unlock(bucket_mutex + bucket);
  if (delta_torrentcount)
    atomic_fetch_add_explicit(&g_torrent_count, (size_t)delta_torrentcount, memory_order_relaxed);
}

void mutex_bucket_unlock_by_hash(ot_hash const hash, int delta_torrentcount) {
  int bucket = bucket_from_hash(hash);

  mutex_bucket_invalidate(bucket);
  mutex_bucket_unlock(bucket, delta_torrentcount);
}

size_t mutex_get_torrent_count(void) { return atomic_load_explicit(&g_torrent_count, memory_order_relaxed); }

void mutex_init(void) {
  memset(summaries, 0, sizeof(summaries));
  size_t i;
  for (i = 0; i < OT_BUCKET_COUNT; ++i)
    pthread_mutex_init(bucket_mutex + i, NULL);
  memset(all_torrents, 0, sizeof(all_torrents));
}

void mutex_deinit(void) {
  size_t i;
  for (i = 0; i < OT_BUCKET_COUNT; ++i)
    pthread_mutex_destroy(bucket_mutex + i);
  memset(all_torrents, 0, sizeof(all_torrents));
}

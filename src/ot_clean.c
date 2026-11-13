/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ot_accesslist.h"
#include "ot_clean.h"
#include "ot_mutex.h"
#include "ot_stats.h"
#include "ot_vector.h"
#include "trackerlogic.h"

ot_time g_empty_torrent_timeout = OT_TORRENT_TIMEOUT;

static ssize_t clean_single_bucket(ot_peer *peers, size_t peer_count, size_t peer_size, time_t timedout,
                                   size_t *removed_seeders) {
  ot_peer *last_peer, *insert_point;

  if (!peer_count)
    return 0;

  last_peer = peers + peer_count * peer_size;

  while (peers < last_peer) {
    time_t timediff = timedout + OT_PEERTIME(peers, peer_size);
    if (timediff >= OT_PEER_TIMEOUT)
      break;
    OT_PEERTIME(peers, peer_size) = timediff;
    peers += peer_size;
  }

  for (insert_point = peers; peers < last_peer; peers += peer_size) {
    time_t timediff = timedout + OT_PEERTIME(peers, peer_size);

    if (timediff < OT_PEER_TIMEOUT) {
      OT_PEERTIME(peers, peer_size) = timediff;
      memcpy(insert_point, peers, peer_size);
      insert_point += peer_size;
    } else if (OT_PEERFLAG_D(peers, peer_size) & PEER_FLAG_SEEDING)
      (*removed_seeders)++;
  }

  return (peers - insert_point) / peer_size;
}

static void clean_family_vector(ot_vector *peer_vector, size_t peer_size, ot_time timedout, size_t *removed_seeders) {
  ot_vector *bucket = peer_vector;
  size_t num_buckets = 1, peer_count;

  if (OT_VECTOR_HASBUCKETS(peer_vector)) {
    num_buckets = peer_vector->size;
    bucket = (ot_vector *)peer_vector->data;
  }

  while (num_buckets--) {
    size_t removed_peers = clean_single_bucket(bucket->data, bucket->size, peer_size, timedout, removed_seeders);
    bucket->size -= removed_peers;
    if (removed_peers)
      vector_fixup_peers(bucket, peer_size);

    ++bucket;
  }

  peer_count = vector_peer_count(peer_vector);

  if (!peer_count) {
    free_peer_vector(peer_vector);
    memset(peer_vector, 0, sizeof(*peer_vector));
    return;
  }

  if ((peer_count > OT_PEER_BUCKET_MINCOUNT) || OT_VECTOR_HASBUCKETS(peer_vector))
    vector_redistribute_buckets(peer_vector, peer_size, peer_count);
}

int clean_single_torrent(ot_torrent *torrent) {
  ot_time timedout = time_since_minutes(torrent->base);
  ot_peerlist *peer_list = torrent->peer_list;
  size_t removed_seeders = 0;

  if (!timedout)
    return 0;

  if (timedout > g_torrent_timeout)
    return 1;

  if (timedout > OT_PEER_TIMEOUT && !peer_list)
    return (torrent->down_count && timedout <= g_empty_torrent_timeout) ? 0 : 1;

  if (timedout > OT_PEER_TIMEOUT)
    timedout = OT_PEER_TIMEOUT;

  if (peer_list) {
    clean_family_vector(&peer_list->peers6, OT_PEER_SIZE6, timedout, &removed_seeders);
    clean_family_vector(&peer_list->peers4, OT_PEER_SIZE4, timedout, &removed_seeders);
    peer_list->seed_count -= removed_seeders;

    if (!vector_peer_count(&peer_list->peers6) && !vector_peer_count(&peer_list->peers4)) {
      free_peerlist(peer_list);
      torrent->peer_list = peer_list = NULL;
    }
  }

  if (peer_list)
    torrent->base = time_now_minutes();
  else {

    ot_time now = time_now_minutes();
    torrent->base = now > OT_PEER_TIMEOUT ? (uint32_t)(now - OT_PEER_TIMEOUT) : 0;
  }
  return 0;
}

static int g_clean_pipe[2] = {-1, -1};

static void clean_sleep(void) {
  struct pollfd pfd;

  pfd.fd = g_clean_pipe[0];
  pfd.events = POLLIN;
  pfd.revents = 0;

  poll(&pfd, 1, OT_CLEAN_SLEEP / 1000);
}

static void clean_bucket(size_t bucket) {
  ot_vector *torrents_list = mutex_bucket_lock((int)bucket);
  size_t toffs;
  int delta_torrentcount = 0;

  for (toffs = 0; toffs < torrents_list->size; ++toffs) {
    ot_torrent *torrent = ((ot_torrent *)(torrents_list->data)) + toffs;
    if (clean_single_torrent(torrent)) {
      vector_remove_torrent(torrents_list, torrent);
      --delta_torrentcount;
      --toffs;
    }
  }
  mutex_bucket_invalidate((int)bucket);
  mutex_bucket_unlock((int)bucket, delta_torrentcount);
}

static void *clean_worker(void *args) {
  (void)args;
  while (1) {
    size_t bucket = OT_BUCKET_COUNT;
    while (bucket) {
      size_t todo = bucket < OT_CLEAN_BUCKETS_PER_WAKE ? bucket : OT_CLEAN_BUCKETS_PER_WAKE;

      while (todo--)
        clean_bucket(--bucket);

      if (!tracker_running)
        return NULL;
      clean_sleep();
    }
    stats_cleanup();
#ifdef WANT_ACCESSLIST
    accesslist_cleanup();
#endif
  }
  return NULL;
}

static pthread_t thread_id;
void clean_init(void) {
  if (pipe(g_clean_pipe) == -1)
    fprintf(stderr,
            "Warning: the cleaner has no pipe to be woken through and will take up to one sleep interval to stop.\n");
  if (pthread_create(&thread_id, NULL, clean_worker, NULL))
    exerr("Cannot create cleanup worker thread.");
}

void clean_deinit(void) {
  const char byte = 0;

  (void)!write(g_clean_pipe[1], &byte, 1);
  pthread_join(thread_id, NULL);

  close(g_clean_pipe[0]);
  close(g_clean_pipe[1]);
}

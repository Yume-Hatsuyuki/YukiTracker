/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ot_accesslist.h"
#include "ot_clean.h"
#include "diagnostics.h"
#include "ot_fmt.h"
#include "ot_fullscrape.h"
#include "ot_http.h"
#include "ot_ip.h"
#include "ot_livesync.h"
#include "ot_mutex.h"
#include "ot_workqueue.h"
#include "ot_random.h"
#include "ot_stats.h"
#include "ot_udp.h"
#include "ot_vector.h"
#include "trackerlogic.h"

int g_max_scrape_http = 64, g_max_scrape_udp = 74, g_key_minutes = 60;
double g_min_ratio = 0.5;
int g_http_read_timeout = OT_CLIENT_TIMEOUT, g_http_write_timeout = 900;
int g_peer_timeout = 45, g_torrent_timeout = 1440;
int g_announce_interval = 1800, g_announce_jitter = 360, g_default_numwant = 50;
int g_max_http = 200, g_max_udp4 = 200, g_max_udp6 = 66, g_keepalive = 0;

size_t return_peers_for_torrent(struct ot_workstruct *ws, ot_torrent *torrent, size_t amount, char *reply,
                                PROTO_FLAG proto);

void free_peer_vector(ot_vector *peer_vector) {
  if (OT_VECTOR_HASBUCKETS(peer_vector))
    vector_clean_list((ot_vector *)peer_vector->data, peer_vector->size);
  else
    free(peer_vector->data);
}

void free_peerlist(ot_peerlist *peer_list) {
  if (!peer_list)
    return;
  free_peer_vector(&peer_list->peers6);
  free_peer_vector(&peer_list->peers4);
  free(peer_list);
}

void add_torrent_from_saved_state(ot_hash const hash, ot_time age, size_t down_count) {
  int exactmatch;
  ot_time now = time_now_minutes();
  ot_torrent *torrent;
  ot_vector *torrents_list;

  if (age > g_torrent_timeout)
    return;

  torrents_list = mutex_bucket_lock_by_hash(hash);

  if (!accesslist_hashisvalid(hash)) {
    mutex_bucket_unlock_by_hash(hash, 0);
    return;
  }

  torrent = vector_find_or_insert(torrents_list, (void *)hash, sizeof(ot_torrent), OT_HASH_COMPARE_SIZE, &exactmatch);
  if (!torrent || exactmatch) {
    mutex_bucket_unlock_by_hash(hash, 0);
    return;
  }

  memset(torrent, 0, sizeof(ot_torrent));
  memcpy(torrent->hash, hash, sizeof(ot_hash));
  torrent->base = now > age ? (uint32_t)(now - age) : 0;
  torrent->down_count = (uint32_t)down_count;

  mutex_bucket_unlock_by_hash(hash, 1);
}

size_t add_peer_to_torrent_and_return_peers(PROTO_FLAG proto, struct ot_workstruct *ws, size_t amount) {
  int exactmatch, delta_torrentcount = 0, completed = 0;
  unsigned renew_age = 0;
  ot_torrent *torrent;
  ot_peer *peer_dest;
  ot_vector *torrents_list = mutex_bucket_lock_by_hash(*ws->hash);
  ot_peerlist *peer_list;
  size_t peer_size;
  ot_peer const *peer_src = peer_from_peer6(&ws->peer, &peer_size);

  if (!accesslist_hashisvalid(*ws->hash)) {
    mutex_bucket_unlock_by_hash(*ws->hash, 0);
    if (proto == FLAG_TCP) {
      const char invalid_hash[] =
          "d14:failure reason63:Requested download is not authorized for use with this tracker.e";
      memcpy(ws->reply, invalid_hash, strlen(invalid_hash));
      return strlen(invalid_hash);
    }
    if (proto == FLAG_UDP) {
      ((uint32_t *)ws->reply)[0] = htonl(OT_CLIENT_REJECT_INTERVAL_RANDOM);
      ((uint32_t *)ws->reply)[1] = 0;
      ((uint32_t *)ws->reply)[2] = 0;
      return 12;
    }
    return 0;
  }

  torrent =
      vector_find_or_insert(torrents_list, (void *)ws->hash, sizeof(ot_torrent), OT_HASH_COMPARE_SIZE, &exactmatch);
  if (!torrent) {
    mutex_bucket_unlock_by_hash(*ws->hash, 0);
    return 0;
  }

  if (!exactmatch) {

    memset(torrent, 0, sizeof(ot_torrent));
    memcpy(torrent->hash, *ws->hash, sizeof(ot_hash));
    delta_torrentcount = 1;
  } else
    clean_single_torrent(torrent);

  torrent->base = time_now_minutes();

  if (!torrent->peer_list && !(torrent->peer_list = calloc(1, sizeof(ot_peerlist)))) {
    if (delta_torrentcount)
      vector_remove_torrent(torrents_list, torrent);
    mutex_bucket_unlock_by_hash(*ws->hash, 0);
    return 0;
  }
  peer_list = torrent->peer_list;

  peer_dest = vector_find_or_insert_peer(peer_size == OT_PEER_SIZE6 ? &peer_list->peers6 : &peer_list->peers4, peer_src,
                                         peer_size, &exactmatch);
  if (!peer_dest) {
    mutex_bucket_unlock_by_hash(*ws->hash, delta_torrentcount);
    return 0;
  }

  OT_PEERTIME(ws->peer, OT_PEER_SIZE6) = 0;

  /* Sanitize flags: Whoever claims to have completed download, must be a seeder */
  if ((OT_PEERFLAG(ws->peer) & (PEER_FLAG_COMPLETED | PEER_FLAG_SEEDING)) == PEER_FLAG_COMPLETED)
    OT_PEERFLAG(ws->peer) ^= PEER_FLAG_COMPLETED;

  if (!exactmatch) {

#ifdef WANT_SYNC_LIVE
    if (proto == FLAG_MCA)
      OT_PEERFLAG(ws->peer) |= PEER_FLAG_FROM_SYNC;
    else
      livesync_tell(ws);
#endif

    if (OT_PEERFLAG(ws->peer) & PEER_FLAG_COMPLETED) {
      torrent->down_count++;
      completed = 1;
    }
    if (OT_PEERFLAG(ws->peer) & PEER_FLAG_SEEDING)
      peer_list->seed_count++;

  } else {
    renew_age = OT_PEERTIME(peer_dest, peer_size);
    stats_issue_event(ws, EVENT_RENEW, 0, renew_age);
#ifdef WANT_SPOT_WOODPECKER
    if ((OT_PEERTIME(peer_dest, peer_size) > 0) && (OT_PEERTIME(peer_dest, peer_size) < 20))
      stats_issue_event(ws, EVENT_WOODPECKER, 0, (uintptr_t)&ws->peer);
#endif
#ifdef WANT_SYNC_LIVE

    if (proto != FLAG_MCA) {
      if (OT_PEERTIME(peer_dest, peer_size) > OT_CLIENT_SYNC_RENEW_BOUNDARY ||
          (!(OT_PEERFLAG_D(peer_dest, peer_size) & PEER_FLAG_COMPLETED) &&
           (OT_PEERFLAG(ws->peer) & PEER_FLAG_COMPLETED)))
        livesync_tell(ws);
    }
#endif

    if ((OT_PEERFLAG_D(peer_dest, peer_size) & PEER_FLAG_SEEDING) && !(OT_PEERFLAG(ws->peer) & PEER_FLAG_SEEDING))
      peer_list->seed_count--;
    if (!(OT_PEERFLAG_D(peer_dest, peer_size) & PEER_FLAG_SEEDING) && (OT_PEERFLAG(ws->peer) & PEER_FLAG_SEEDING))
      peer_list->seed_count++;
    if (!(OT_PEERFLAG_D(peer_dest, peer_size) & PEER_FLAG_COMPLETED) && (OT_PEERFLAG(ws->peer) & PEER_FLAG_COMPLETED)) {
      torrent->down_count++;
      completed = 1;
    }
    if (OT_PEERFLAG_D(peer_dest, peer_size) & PEER_FLAG_COMPLETED)
      OT_PEERFLAG(ws->peer) |= PEER_FLAG_COMPLETED;
  }

  memcpy(peer_dest, peer_src, peer_size);
#ifdef WANT_SYNC
  if (proto == FLAG_MCA)
    ws->reply_size = 0;
  else
#endif
    ws->reply_size = return_peers_for_torrent(ws, torrent, amount, ws->reply, proto);
  mutex_bucket_unlock_by_hash(*ws->hash, delta_torrentcount);
  if (busy_slots && renew_age)
    diag_renew(*(ot_ip6 *)ws->peer, renew_age);

  if (completed)
    stats_issue_event(ws, EVENT_COMPLETED, 0, 0);
  return ws->reply_size;
}

static size_t return_peers_all(ot_vector *peer_vector, size_t peer_size, size_t peer_count, char *reply) {
  size_t bucket, num_buckets = 1;
  ot_vector *bucket_list = peer_vector;
  size_t compare_size = OT_PEER_COMPARE_SIZE_FROM_PEER_SIZE(peer_size);
  size_t result = compare_size * peer_count;
  char *r_end = reply + result;

  if (OT_VECTOR_HASBUCKETS(peer_vector)) {
    num_buckets = bucket_list->size;
    bucket_list = (ot_vector *)bucket_list->data;
  }

  for (bucket = 0; bucket < num_buckets; ++bucket) {
    ot_peer *peers = bucket_list[bucket].data;
    size_t peer_count = bucket_list[bucket].size;
    while (peer_count--) {
      if (OT_PEERFLAG_D(peers, peer_size) & PEER_FLAG_SEEDING) {
        r_end -= compare_size;
        memcpy(r_end, peers, compare_size);
      } else {
        memcpy(reply, peers, compare_size);
        reply += compare_size;
      }
      peers += peer_size;
    }
  }
  return result;
}

static size_t return_peers_selection(struct ot_workstruct *ws, ot_vector *peer_vector, size_t peer_size, size_t amount,
                                     size_t peer_count, char *reply) {
  size_t bucket_offset, bucket_index = 0, num_buckets = 1;
  ot_vector *bucket_list = peer_vector;
  unsigned int shifted_pc = peer_count;
  unsigned int shifted_step = 0;
  unsigned int shift = 0;
  size_t compare_size = OT_PEER_COMPARE_SIZE_FROM_PEER_SIZE(peer_size);
  size_t result = compare_size * amount;
  char *r_end = reply + result;

  if (OT_VECTOR_HASBUCKETS(peer_vector)) {
    num_buckets = bucket_list->size;
    bucket_list = (ot_vector *)bucket_list->data;
  }

#define MAXPRECBIT (1 << (8 * sizeof(int) - 3))
  while (!(shifted_pc & MAXPRECBIT)) {
    shifted_pc <<= 1;
    shift++;
  }
  shifted_step = shifted_pc / amount;
#undef MAXPRECBIT

  bucket_offset = nrand48(ws->rand48_state) % peer_count;

  while (amount--) {
    ot_peer *peer;

    unsigned int diff = (((amount + 1) * shifted_step) >> shift) - ((amount * shifted_step) >> shift);
    bucket_offset += 1 + nrand48(ws->rand48_state) % diff;

    while (bucket_offset >= bucket_list[bucket_index].size) {
      bucket_offset -= bucket_list[bucket_index].size;
      bucket_index = (bucket_index + 1) % num_buckets;
    }
    peer = (ot_peer *)bucket_list[bucket_index].data + peer_size * bucket_offset;
    if (OT_PEERFLAG_D(peer, peer_size) & PEER_FLAG_SEEDING) {
      r_end -= compare_size;
      memcpy(r_end, peer, compare_size);
    } else {
      memcpy(reply, peer, compare_size);
      reply += compare_size;
    }
  }
  return result;
}

static size_t return_peers_for_torrent_udp(struct ot_workstruct *ws, ot_torrent *torrent, size_t amount, char *reply) {
  char *r = reply;
  size_t peer_size = peer_size_from_peer6(&ws->peer);
  ot_peerlist *peer_list = torrent->peer_list;
  ot_vector *family = peer_size == OT_PEER_SIZE6 ? &peer_list->peers6 : &peer_list->peers4;
  size_t list_count = vector_peer_count(family);
  size_t peer_count = torrent_peer_count(torrent);
  size_t seed_count = torrent_seed_count(torrent);

  if (amount > list_count)
    amount = list_count;

  *(uint32_t *)(r + 0) = htonl(OT_CLIENT_REQUEST_INTERVAL_RANDOM);
  *(uint32_t *)(r + 4) = htonl(peer_count - seed_count);
  *(uint32_t *)(r + 8) = htonl(seed_count);
  r += 12;

  if (amount) {
    if (amount == list_count)
      r += return_peers_all(family, peer_size, list_count, r);
    else
      r += return_peers_selection(ws, family, peer_size, amount, list_count, r);
  }
  return r - reply;
}

static size_t return_peers_for_torrent_tcp(struct ot_workstruct *ws, ot_torrent *torrent, size_t amount, char *reply) {
  char *r = reply;
  const char *r_end = ws->outbuf + G_OUTBUF_SIZE;
  int erval = OT_CLIENT_REQUEST_INTERVAL_RANDOM;
  ot_peerlist *peer_list = torrent->peer_list;
  size_t count6 = vector_peer_count(&peer_list->peers6);
  size_t count4 = vector_peer_count(&peer_list->peers4);
  size_t seed_count = peer_list->seed_count;
  size_t down_count = torrent->down_count;
  size_t peer_count = count6 + count4 - seed_count;

  size_t amount_v4 = count4;
  size_t amount_v6 = count6;

  if (amount_v4 + amount_v6 > amount) {
    size_t amount_left, percent_v6 = 0, percent_v4 = 0, left_v6, left_v4;
    const size_t SCALE = 1024;

    if (amount / 4 <= amount_v4)
      amount_v4 = amount / 4;
    if (amount / 4 <= amount_v6)
      amount_v6 = amount / 4;

    amount_left = amount - (amount_v4 + amount_v6);

    left_v4 = count4 - amount_v4;
    left_v6 = count6 - amount_v6;

    if (left_v4 + left_v6) {
      percent_v4 = (SCALE * left_v4) / (left_v4 + left_v6);
      percent_v6 = (SCALE * left_v6) / (left_v4 + left_v6);
    }

    amount_v4 += (amount_left * percent_v4) / SCALE;
    amount_v6 += (amount_left * percent_v6) / SCALE;

    if (amount_v4 + amount_v6 < amount && amount_v6 < count6)
      ++amount_v6;
    if (amount_v4 + amount_v6 < amount && amount_v4 < count4)
      ++amount_v4;
  }

  fmt_append(&r, r_end, "d8:completei%zde10:downloadedi%zde10:incompletei%zde8:intervali%ie12:min intervali%ie",
             seed_count, down_count, peer_count, erval, (int)(g_announce_interval * g_min_ratio));

  if (amount_v4) {
    fmt_append(&r, r_end, PEERS_BENCODED4 "%zd:", OT_PEER_COMPARE_SIZE4 * amount_v4);
    if (amount_v4 == count4)
      r += return_peers_all(&peer_list->peers4, OT_PEER_SIZE4, count4, r);
    else
      r += return_peers_selection(ws, &peer_list->peers4, OT_PEER_SIZE4, amount_v4, count4, r);
  }

  if (amount_v6) {
    fmt_append(&r, r_end, PEERS_BENCODED6 "%zd:", OT_PEER_COMPARE_SIZE6 * amount_v6);
    if (amount_v6 == count6)
      r += return_peers_all(&peer_list->peers6, OT_PEER_SIZE6, count6, r);
    else
      r += return_peers_selection(ws, &peer_list->peers6, OT_PEER_SIZE6, amount_v6, count6, r);
  }

  fmt_append(&r, r_end, "e");

  return r - reply;
}

size_t return_peers_for_torrent(struct ot_workstruct *ws, ot_torrent *torrent, size_t amount, char *reply,
                                PROTO_FLAG proto) {
  return proto == FLAG_TCP ? return_peers_for_torrent_tcp(ws, torrent, amount, reply)
                           : return_peers_for_torrent_udp(ws, torrent, amount, reply);
}

size_t return_udp_scrape_for_torrent(ot_hash const hash, char *reply) {
  int exactmatch, delta_torrentcount = 0;
  ot_vector *torrents_list = mutex_bucket_lock_by_hash(hash);
  ot_torrent *torrent = vector_binary_search(hash, torrents_list->data, torrents_list->size, sizeof(ot_torrent),
                                             OT_HASH_COMPARE_SIZE, &exactmatch);

  if (!exactmatch) {
    memset(reply, 0, 12);
  } else {
    uint32_t *r = (uint32_t *)reply;

    if (clean_single_torrent(torrent)) {
      vector_remove_torrent(torrents_list, torrent);
      memset(reply, 0, 12);
      delta_torrentcount = -1;
    } else {
      r[0] = htonl(torrent_seed_count(torrent));
      r[1] = htonl(torrent->down_count);
      r[2] = htonl(torrent_peer_count(torrent) - torrent_seed_count(torrent));
    }
  }
  mutex_bucket_unlock_by_hash(hash, delta_torrentcount);
  return 12;
}

void return_tcp_scrape_for_torrent(ot_hash const *hash_list, size_t amount, char **reply, const char *reply_end) {
  int exactmatch;
  size_t i;

  fmt_append(reply, reply_end, "d5:filesd");

  for (i = 0; i < amount; ++i) {
    int delta_torrentcount = 0;
    ot_hash const *hash = hash_list + i;
    ot_vector *torrents_list = mutex_bucket_lock_by_hash(*hash);
    ot_torrent *torrent = vector_binary_search(hash, torrents_list->data, torrents_list->size, sizeof(ot_torrent),
                                               OT_HASH_COMPARE_SIZE, &exactmatch);

    if (exactmatch) {
      if (clean_single_torrent(torrent)) {
        vector_remove_torrent(torrents_list, torrent);
        delta_torrentcount = -1;
      } else {
        fmt_append(reply, reply_end, "20:");
        fmt_bytes(reply, reply_end, hash, sizeof(ot_hash));
        size_t seed_count = torrent_seed_count(torrent);
        size_t peer_count = torrent_peer_count(torrent);
        fmt_append(reply, reply_end, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee", seed_count,
                   (size_t)torrent->down_count, peer_count - seed_count);
      }
    }
    mutex_bucket_unlock_by_hash(*hash, delta_torrentcount);
  }

  fmt_append(reply, reply_end, "ee");
}

size_t remove_peer_from_torrent(PROTO_FLAG proto, struct ot_workstruct *ws) {
  int exactmatch;
  ot_vector *torrents_list = mutex_bucket_lock_by_hash(*ws->hash);
  ot_torrent *torrent = vector_binary_search(ws->hash, torrents_list->data, torrents_list->size, sizeof(ot_torrent),
                                             OT_HASH_COMPARE_SIZE, &exactmatch);
  size_t peer_size;
  ot_peer const *peer_src = peer_from_peer6(&ws->peer, &peer_size);
  size_t peer_count = 0, seed_count = 0;

#ifdef WANT_SYNC_LIVE
  if (proto != FLAG_MCA) {
    OT_PEERFLAG(ws->peer) |= PEER_FLAG_STOPPED;
    livesync_tell(ws);
  }
#endif

  if (exactmatch && torrent->peer_list) {
    ot_vector *family = peer_size == OT_PEER_SIZE6 ? &torrent->peer_list->peers6 : &torrent->peer_list->peers4;
    if (vector_remove_peer(family, peer_src, peer_size) == 2)
      torrent->peer_list->seed_count--;

    peer_count = torrent_peer_count(torrent);
    seed_count = torrent_seed_count(torrent);
  }

  if (proto == FLAG_TCP) {
    int erval = OT_CLIENT_REQUEST_INTERVAL_RANDOM;
    char *r = ws->reply;

    fmt_append(&r, ws->outbuf + G_OUTBUF_SIZE,
               "d8:completei%zde10:incompletei%zde8:intervali%ie12:min intervali%ie%s0:e", seed_count,
               peer_count - seed_count, erval, (int)(g_announce_interval * g_min_ratio),
               peer_size == OT_PEER_SIZE6 ? PEERS_BENCODED6 : PEERS_BENCODED4);
    ws->reply_size = r - ws->reply;
  }

  if (proto == FLAG_UDP) {
    ((uint32_t *)ws->reply)[2] = htonl(OT_CLIENT_REQUEST_INTERVAL_RANDOM);
    ((uint32_t *)ws->reply)[3] = htonl(peer_count - seed_count);
    ((uint32_t *)ws->reply)[4] = htonl(seed_count);
    ws->reply_size = 20;
  }

  mutex_bucket_unlock_by_hash(*ws->hash, 0);
  return ws->reply_size;
}

void iterate_all_torrents(int (*for_each)(ot_torrent *torrent, uintptr_t data), uintptr_t data) {
  size_t bucket, j;

  for (bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket) {
    ot_vector *torrents_list = mutex_bucket_lock(bucket);
    ot_torrent *torrents = (ot_torrent *)(torrents_list->data);

    for (j = 0; j < torrents_list->size; ++j)
      if (for_each(torrents + j, data))
        break;

    mutex_bucket_unlock(bucket, 0);
    if (!tracker_running)
      return;
  }
}

ot_peer *peer_from_peer6(ot_peer6 *peer, size_t *peer_size) {
  ot_ip6 *ip = (ot_ip6 *)peer;
  if (!ip_is_v4mapped(ip)) {
    *peer_size = OT_PEER_SIZE6;
    return (ot_peer *)peer;
  }
  *peer_size = OT_PEER_SIZE4;
  return (ot_peer *)(((uint8_t *)peer) + 12);
}

size_t peer_size_from_peer6(ot_peer6 *peer) {
  ot_ip6 *ip = (ot_ip6 *)peer;
  if (!ip_is_v4mapped(ip))
    return OT_PEER_SIZE6;
  return OT_PEER_SIZE4;
}

void exerr(const char *message) {
  fprintf(stderr, "%s\n", message);
  exit(111);
}

void trackerlogic_init(void) {
  g_tracker_id = random_uint32();

  if (!g_stats_path)
    g_stats_path = "stats";
  g_stats_path_len = strlen(g_stats_path);

  mutex_init();
  workqueue_init();
  clean_init();
  fullscrape_init();
  accesslist_init();
  stats_init();
}

int workstruct_init(struct ot_workstruct *ws, size_t inbuf_size) {
  memset(ws, 0, sizeof(*ws));
  ws->inbuf = malloc(inbuf_size);
  ws->outbuf = malloc(G_OUTBUF_SIZE);
  if (!ws->inbuf || !ws->outbuf) {
    free(ws->inbuf);
    free(ws->outbuf);
    return -1;
  }

  random_bytes(ws->rand48_state, sizeof(ws->rand48_state));

  stats_counters_register(ws);
  return 0;
}

void workstruct_deinit(struct ot_workstruct *ws) {

  stats_counters_retire(ws);

  free(ws->inbuf);
  free(ws->outbuf);
}

void trackerlogic_deinit(void) {
  size_t bucket, j;

  clean_deinit();
  stats_deinit();
  accesslist_deinit();
  fullscrape_deinit();

  for (bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket) {
    ot_vector *torrents_list = mutex_bucket_lock(bucket);
    int delta_torrentcount = 0;
    if (torrents_list->size) {
      for (j = 0; j < torrents_list->size; ++j) {
        ot_torrent *torrent = ((ot_torrent *)(torrents_list->data)) + j;
        free_peerlist(torrent->peer_list);
        delta_torrentcount -= 1;
      }
      free(torrents_list->data);
    }
    mutex_bucket_unlock(bucket, delta_torrentcount);
  }

  workqueue_deinit();
  mutex_deinit();
}

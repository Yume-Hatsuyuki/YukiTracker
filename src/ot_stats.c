/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
 It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#ifdef WANT_SYSLOGS
#include <syslog.h>
#endif

#include "ot_accesslist.h"
#include "ot_event.h"
#include "ot_hex.h"
#include "ot_iovec.h"
#include "ot_ip.h"
#include "ot_mutex.h"
#include "ot_workqueue.h"
#include "ot_fmt.h"
#include "ot_stats.h"
#include "trackerlogic.h"

#ifndef NO_FULLSCRAPE_LOGGING
#define LOG_TO_STDERR(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG_TO_STDERR(...)
#endif

static void stats_make(size_t *iovec_entries, struct iovec **iovector, ot_tasktype mode);
#define OT_STATS_TMPSIZE 8192

static struct ot_workstruct *g_counter_contexts;
static ot_counter g_retired[OT_COUNTER_COUNT];
static pthread_mutex_t g_counter_mutex = PTHREAD_MUTEX_INITIALIZER;

void stats_counters_register(struct ot_workstruct *ws) {
  pthread_mutex_lock(&g_counter_mutex);
  ws->counters_next = g_counter_contexts;
  g_counter_contexts = ws;
  pthread_mutex_unlock(&g_counter_mutex);
}

void stats_counters_retire(struct ot_workstruct *ws) {
  struct ot_workstruct **link;
  size_t i;

  pthread_mutex_lock(&g_counter_mutex);
  for (link = &g_counter_contexts; *link; link = &(*link)->counters_next)
    if (*link == ws) {
      *link = ws->counters_next;
      break;
    }

  for (i = 0; i < OT_COUNTER_COUNT; ++i)
    atomic_fetch_add_explicit(g_retired + i, atomic_load_explicit(ws->counters + i, memory_order_relaxed),
                              memory_order_relaxed);
  pthread_mutex_unlock(&g_counter_mutex);
}

static void counters_total(unsigned long long *total) {
  struct ot_workstruct *ws;
  size_t i;

  pthread_mutex_lock(&g_counter_mutex);
  for (i = 0; i < OT_COUNTER_COUNT; ++i)
    total[i] = atomic_load_explicit(g_retired + i, memory_order_relaxed);
  for (ws = g_counter_contexts; ws; ws = ws->counters_next)
    for (i = 0; i < OT_COUNTER_COUNT; ++i)
      total[i] += atomic_load_explicit(ws->counters + i, memory_order_relaxed);
  pthread_mutex_unlock(&g_counter_mutex);
}

#define COUNT(index, by)                                                                                               \
  atomic_fetch_add_explicit(ws->counters + (index), (unsigned long long)(by), memory_order_relaxed)

static const char *ot_failed_request_names[] = {"302 Redirect",
                                                "400 Parse Error",
                                                "400 Invalid Parameter",
                                                "400 Invalid Parameter (compact=0)",
                                                "400 Not Modest",
                                                "402 Payment Required",
                                                "403 Access Denied",
                                                "404 Not found",
                                                "500 Internal Server Error"};

static time_t ot_start_time;

#ifdef WANT_SPOT_WOODPECKER
#define STATS_NETWORK_NODE_BITWIDTH 4
#define STATS_NETWORK_NODE_COUNT (1 << STATS_NETWORK_NODE_BITWIDTH)

#define __BYTE(P, D) (((uint8_t *)(P))[(D) / 8])
#define __MSK (STATS_NETWORK_NODE_COUNT - 1)
#define __SHFT(D) (((D) ^ STATS_NETWORK_NODE_BITWIDTH) & STATS_NETWORK_NODE_BITWIDTH)

#define __LDR(P, D) ((__BYTE((P), (D)) >> __SHFT((D))) & __MSK)
#define __STR(P, D, V) __BYTE((P), (D)) = (__BYTE((P), (D)) & ~(__MSK << __SHFT((D)))) | ((V) << __SHFT((D)))

#if 0

#define STATS_NETWORK_NODE_MAXDEPTH (68 - STATS_NETWORK_NODE_BITWIDTH)
#define STATS_NETWORK_NODE_LIMIT (48 - STATS_NETWORK_NODE_BITWIDTH)
#endif
#define STATS_NETWORK_NODE_MAXDEPTH (28 - STATS_NETWORK_NODE_BITWIDTH)
#define STATS_NETWORK_NODE_LIMIT (24 - STATS_NETWORK_NODE_BITWIDTH)

typedef union stats_network_node stats_network_node;
union stats_network_node {
  size_t counters[STATS_NETWORK_NODE_COUNT];
  stats_network_node *children[STATS_NETWORK_NODE_COUNT];
};

static int stat_increase_network_count(stats_network_node **pnode, int depth, uintptr_t ip) {
  int foo = __LDR(ip, depth);
  stats_network_node *node;

  if (!*pnode) {
    *pnode = malloc(sizeof(stats_network_node));
    if (!*pnode)
      return -1;
    memset(*pnode, 0, sizeof(stats_network_node));
  }
  node = *pnode;

  if (depth < STATS_NETWORK_NODE_MAXDEPTH)
    return stat_increase_network_count(node->children + foo, depth + STATS_NETWORK_NODE_BITWIDTH, ip);

  node->counters[foo]++;
  return 0;
}

static int stats_shift_down_network_count(stats_network_node **node, int depth, int shift) {
  size_t i, rest = 0;

  if (!*node)
    return 0;

  for (i = 0; i < STATS_NETWORK_NODE_COUNT; ++i)
    if (depth < STATS_NETWORK_NODE_MAXDEPTH)
      rest += stats_shift_down_network_count((*node)->children + i, depth + STATS_NETWORK_NODE_BITWIDTH, shift);
    else
      rest += (*node)->counters[i] >>= shift;

  if (!rest) {
    free(*node);
    *node = NULL;
  }

  return rest;
}

static size_t stats_get_highscore_networks(stats_network_node *node, int depth, ot_ip6 node_value, size_t *scores,
                                           ot_ip6 *networks, int network_count, int limit) {
  size_t i, score = 0;

  if (!node)
    return 0;

  if (depth < limit) {
    for (i = 0; i < STATS_NETWORK_NODE_COUNT; ++i)
      if (node->children[i]) {
        __STR(node_value, depth, i);
        score += stats_get_highscore_networks(node->children[i], depth + STATS_NETWORK_NODE_BITWIDTH, node_value,
                                              scores, networks, network_count, limit);
      }
    return score;
  }

  if (depth > limit && depth < STATS_NETWORK_NODE_MAXDEPTH) {
    for (i = 0; i < STATS_NETWORK_NODE_COUNT; ++i)
      if (node->children[i])
        score += stats_get_highscore_networks(node->children[i], depth + STATS_NETWORK_NODE_BITWIDTH, node_value,
                                              scores, networks, network_count, limit);
    return score;
  }

  if (depth > limit && depth == STATS_NETWORK_NODE_MAXDEPTH) {
    for (i = 0; i < STATS_NETWORK_NODE_COUNT; ++i)
      score += node->counters[i];
    return score;
  }

  for (i = 0; i < STATS_NETWORK_NODE_COUNT; ++i) {
    int j = 1;
    size_t node_score;

    if (depth == STATS_NETWORK_NODE_MAXDEPTH)
      node_score = node->counters[i];
    else
      node_score = stats_get_highscore_networks(node->children[i], depth + STATS_NETWORK_NODE_BITWIDTH, node_value,
                                                scores, networks, network_count, limit);

    score += node_score;

    if (node_score <= scores[0])
      continue;

    __STR(node_value, depth, i);
    while (j < network_count && node_score > scores[j])
      ++j;
    --j;

    memmove(scores, scores + 1, j * sizeof(*scores));
    memmove(networks, networks + 1, j * sizeof(*networks));
    scores[j] = node_score;
    memcpy(networks + j, node_value, sizeof(*networks));
  }

  return score;
}

static void stats_return_busy_networks(char **reply, const char *reply_end, stats_network_node *tree, size_t amount,
                                       int limit) {
  ot_ip6 networks[amount];
  ot_ip6 node_value;
  size_t scores[amount];
  size_t i;

  memset(scores, 0, sizeof(scores));
  memset(networks, 0, sizeof(networks));
  memset(node_value, 0, sizeof(node_value));

  stats_get_highscore_networks(tree, 0, node_value, scores, networks, amount, limit);

  fmt_append(reply, reply_end, "Networks, limit /%d:\n", limit + STATS_NETWORK_NODE_BITWIDTH);
  for (i = amount; i > 0; --i) {
    if (scores[i - 1]) {
      char ip_readable[64];

      ip_readable[ip_format(ip_readable, networks[i - 1])] = 0;
      fmt_append(reply, reply_end, "%08zd: %s\n", scores[i - 1], ip_readable);
    }
  }
  fmt_append(reply, reply_end, "\n");
}

static stats_network_node *stats_woodpeckers_tree;
static pthread_mutex_t g_woodpeckers_mutex = PTHREAD_MUTEX_INITIALIZER;

static void stats_return_woodpeckers(char **reply, const char *reply_end, int amount) {
  pthread_mutex_lock(&g_woodpeckers_mutex);
  stats_return_busy_networks(reply, reply_end, stats_woodpeckers_tree, amount, STATS_NETWORK_NODE_MAXDEPTH);
  pthread_mutex_unlock(&g_woodpeckers_mutex);
}
#endif

typedef struct {
  unsigned long long torrent_count;
  unsigned long long peer_count;
  unsigned long long seed_count;
} torrent_stats;

static int torrent_statter(ot_torrent *torrent, uintptr_t data) {
  torrent_stats *stats = (torrent_stats *)data;
  stats->torrent_count++;
  stats->peer_count += torrent_peer_count(torrent);
  stats->seed_count += torrent_seed_count(torrent);
  return 0;
}

typedef struct {
  size_t val;
  ot_hash hash;
} ot_record;

static inline void stats_insert_into_highscore(size_t val, ot_record *list, size_t amount, ot_hash *hash) {
  size_t i;
  for (i = 0; (i < amount) && (list[i].val > val); ++i) {
  }

  if (i < amount) {
    memmove(list + i + 1, list + i, (amount - i - 1) * sizeof(ot_record));

    memcpy(&list[i].hash, hash, sizeof(ot_hash));
    list[i].val = val;
  }
}

void stats_top_txt(char **reply, const char *reply_end, size_t amount) {
  size_t j, idx, bucket;
  ot_record top100s[100], top100c[100], top100l[100];
  char hex_out[42];

  if (amount > 100)
    amount = 100;

  memset(top100s, 0, sizeof(top100s));
  memset(top100c, 0, sizeof(top100c));
  memset(top100l, 0, sizeof(top100l));

  for (bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket) {
    ot_vector *torrents_list = mutex_bucket_lock(bucket);
    for (j = 0; j < torrents_list->size; ++j) {
      ot_torrent *torrent = (ot_torrent *)(torrents_list->data) + j;
      size_t peer_count = torrent_peer_count(torrent);
      size_t seed_count = torrent_seed_count(torrent);
      size_t leech_count = peer_count - seed_count;

      stats_insert_into_highscore(peer_count, top100c, amount, &torrent->hash);
      stats_insert_into_highscore(seed_count, top100s, amount, &torrent->hash);
      stats_insert_into_highscore(leech_count, top100l, amount, &torrent->hash);
    }
    mutex_bucket_unlock(bucket, 0);
    if (!tracker_running)
      return;
  }

  fmt_append(reply, reply_end, "Top %zd torrents by peers:\n", amount);
  for (idx = 0; idx < amount; ++idx)
    if (top100c[idx].val)
      fmt_append(reply, reply_end, "\t%zd\t%s\n", top100c[idx].val, hex_from_hash(hex_out, top100c[idx].hash));
  fmt_append(reply, reply_end, "Top %zd torrents by seeds:\n", amount);
  for (idx = 0; idx < amount; ++idx)
    if (top100s[idx].val)
      fmt_append(reply, reply_end, "\t%zd\t%s\n", top100s[idx].val, hex_from_hash(hex_out, top100s[idx].hash));
  fmt_append(reply, reply_end, "Top %zd torrents by leechers:\n", amount);
  for (idx = 0; idx < amount; ++idx)
    if (top100l[idx].val)
      fmt_append(reply, reply_end, "\t%zd\t%s\n", top100l[idx].val, hex_from_hash(hex_out, top100l[idx].hash));
}

static unsigned long events_per_time(unsigned long long events, time_t t) {
  return events / ((unsigned int)t ? (unsigned int)t : 1);
}

static void stats_connections_mrtg(char **reply, const char *reply_end) {
  ot_time t = time_since_seconds(ot_start_time);
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  fmt_append(
      reply, reply_end, "%llu\n%llu\n%i seconds (%i hours)\nYukiTracker connections, %lu conns/s :: %lu success/s.",
      total[OT_COUNTER_TCP_CONNECTIONS] + total[OT_COUNTER_UDP_CONNECTIONS],
      total[OT_COUNTER_TCP_ANNOUNCES] + total[OT_COUNTER_UDP_ANNOUNCES] + total[OT_COUNTER_UDP_CONNECTS], (int)t,
      (int)(t / 3600), events_per_time(total[OT_COUNTER_TCP_CONNECTIONS] + total[OT_COUNTER_UDP_CONNECTIONS], t),
      events_per_time(
          total[OT_COUNTER_TCP_ANNOUNCES] + total[OT_COUNTER_UDP_ANNOUNCES] + total[OT_COUNTER_UDP_CONNECTS], t));
}

static void stats_udpconnections_mrtg(char **reply, const char *reply_end) {
  ot_time t = time_since_seconds(ot_start_time);
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  fmt_append(reply, reply_end,
             "%llu\n%llu\n%i seconds (%i hours)\nYukiTracker udp4 stats, %lu conns/s :: %lu success/s.",
             total[OT_COUNTER_UDP_CONNECTIONS], total[OT_COUNTER_UDP_ANNOUNCES] + total[OT_COUNTER_UDP_CONNECTS],
             (int)t, (int)(t / 3600), events_per_time(total[OT_COUNTER_UDP_CONNECTIONS], t),
             events_per_time(total[OT_COUNTER_UDP_ANNOUNCES] + total[OT_COUNTER_UDP_CONNECTS], t));
}

static void stats_tcpconnections_mrtg(char **reply, const char *reply_end) {
  time_t t = time_since_seconds(ot_start_time);
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  fmt_append(
      reply, reply_end, "%llu\n%llu\n%i seconds (%i hours)\nYukiTracker tcp4 stats, %lu conns/s :: %lu success/s.",
      total[OT_COUNTER_TCP_CONNECTIONS], total[OT_COUNTER_TCP_ANNOUNCES], (int)t, (int)(t / 3600),
      events_per_time(total[OT_COUNTER_TCP_CONNECTIONS], t), events_per_time(total[OT_COUNTER_TCP_ANNOUNCES], t));
}

static void stats_scrape_mrtg(char **reply, const char *reply_end) {
  time_t t = time_since_seconds(ot_start_time);
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  fmt_append(reply, reply_end,
             "%llu\n%llu\n%i seconds (%i hours)\nYukiTracker scrape stats, %lu scrape/s (tcp and udp)",
             total[OT_COUNTER_TCP_SCRAPES], total[OT_COUNTER_UDP_SCRAPES], (int)t, (int)(t / 3600),
             events_per_time((total[OT_COUNTER_TCP_SCRAPES] + total[OT_COUNTER_UDP_SCRAPES]), t));
}

static void stats_fullscrapes_mrtg(char **reply, const char *reply_end) {
  ot_time t = time_since_seconds(ot_start_time);
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  fmt_append(reply, reply_end,
             "%llu\n%llu\n%i seconds (%i hours)\nYukiTracker full scrape stats, %lu conns/s :: %lu bytes/s.",
             total[OT_COUNTER_FULLSCRAPES] * 1000, total[OT_COUNTER_FULLSCRAPE_BYTES], (int)t, (int)(t / 3600),
             events_per_time(total[OT_COUNTER_FULLSCRAPES], t), events_per_time(total[OT_COUNTER_FULLSCRAPE_BYTES], t));
}

static void stats_peers_mrtg(char **reply, const char *reply_end) {
  torrent_stats stats = {0, 0, 0};

  iterate_all_torrents(torrent_statter, (uintptr_t)&stats);

  fmt_append(reply, reply_end, "%llu\n%llu\nYukiTracker serving %llu torrents\nYukiTracker", stats.peer_count,
             stats.seed_count, stats.torrent_count);
}

static void stats_torrents_mrtg(char **reply, const char *reply_end) {
  size_t torrent_count = mutex_get_torrent_count();

  fmt_append(reply, reply_end, "%zd\n%zd\nYukiTracker serving %zd torrents\nYukiTracker", torrent_count, (size_t)0,
             torrent_count);
}

static void stats_httperrors_txt(char **reply, const char *reply_end) {
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  fmt_append(reply, reply_end,
             "302 RED %llu\n400 ... %llu\n400 PAR %llu\n400 COM %llu\n403 IP  %llu\n404 INV %llu\n500 SRV %llu\n",
             total[OT_COUNTER_FAILED + 0], total[OT_COUNTER_FAILED + 1], total[OT_COUNTER_FAILED + 2],
             total[OT_COUNTER_FAILED + 3], total[OT_COUNTER_FAILED + 4], total[OT_COUNTER_FAILED + 5],
             total[OT_COUNTER_FAILED + 6]);
}

static void stats_return_renew_bucket(char **reply, const char *reply_end) {
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  int i;

  for (i = 0; i < OT_PEER_TIMEOUT; ++i)
    fmt_append(reply, reply_end, "%02i %llu\n", i, total[OT_COUNTER_RENEWED + i]);
}

static void stats_return_sync_mrtg(char **reply, const char *reply_end) {
  ot_time t = time_since_seconds(ot_start_time);
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  fmt_append(
      reply, reply_end, "%llu\n%llu\n%i seconds (%i hours)\nYukiTracker connections, %lu conns/s :: %lu success/s.",
      total[OT_COUNTER_SYNCS], 0LL, (int)t, (int)(t / 3600),
      events_per_time(total[OT_COUNTER_TCP_CONNECTIONS] + total[OT_COUNTER_UDP_CONNECTIONS], t),
      events_per_time(
          total[OT_COUNTER_TCP_ANNOUNCES] + total[OT_COUNTER_UDP_ANNOUNCES] + total[OT_COUNTER_UDP_CONNECTS], t));
}

static void stats_return_completed_mrtg(char **reply, const char *reply_end) {
  ot_time t = time_since_seconds(ot_start_time);
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  fmt_append(reply, reply_end, "%llu\n%llu\n%i seconds (%i hours)\nYukiTracker, %lu completed/h.",
             total[OT_COUNTER_COMPLETED], 0LL, (int)t, (int)(t / 3600),
             events_per_time(total[OT_COUNTER_COMPLETED], t / 3600));
}

#ifdef WANT_LOG_NUMWANT
extern unsigned long long numwants[201];
static void stats_return_numwants(char **reply, const char *reply_end) {
  int i;
  for (i = 0; i <= 200; ++i)
    fmt_append(reply, reply_end, "%03d => %llu\n", i, numwants[i]);
}
#endif

static void stats_return_everything(char **reply, const char *reply_end) {
  unsigned long long total[OT_COUNTER_COUNT];

  counters_total(total);

  torrent_stats stats = {0, 0, 0};
  int i;

  iterate_all_torrents(torrent_statter, (uintptr_t)&stats);

  fmt_append(reply, reply_end, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  fmt_append(reply, reply_end, "<stats>\n");
  fmt_append(reply, reply_end, "  <uptime>%llu</uptime>\n", (unsigned long long)time_since_seconds(ot_start_time));
  fmt_append(reply, reply_end, "  <torrents>\n");
  fmt_append(reply, reply_end, "    <count_mutex>%zd</count_mutex>\n", mutex_get_torrent_count());
  fmt_append(reply, reply_end, "    <count_iterator>%llu</count_iterator>\n", stats.torrent_count);
  fmt_append(reply, reply_end, "  </torrents>\n");
  fmt_append(reply, reply_end, "  <peers>\n    <count>%llu</count>\n  </peers>\n", stats.peer_count);
  fmt_append(reply, reply_end, "  <seeds>\n    <count>%llu</count>\n  </seeds>\n", stats.seed_count);
  fmt_append(reply, reply_end, "  <completed>\n    <count>%llu</count>\n  </completed>\n", total[OT_COUNTER_COMPLETED]);
  fmt_append(reply, reply_end, "  <connections>\n");
  fmt_append(reply, reply_end,
             "    <tcp>\n      <accept>%llu</accept>\n      <announce>%llu</announce>\n      <scrape>%llu</scrape>\n   "
             " </tcp>\n",
             total[OT_COUNTER_TCP_CONNECTIONS], total[OT_COUNTER_TCP_ANNOUNCES], total[OT_COUNTER_TCP_SCRAPES]);
  fmt_append(reply, reply_end,
             "    <udp>\n      <overall>%llu</overall>\n      <connect>%llu</connect>\n      "
             "<announce>%llu</announce>\n      <scrape>%llu</scrape>\n      <missmatch>%llu</missmatch>\n    </udp>\n",
             total[OT_COUNTER_UDP_CONNECTIONS], total[OT_COUNTER_UDP_CONNECTS], total[OT_COUNTER_UDP_ANNOUNCES],
             total[OT_COUNTER_UDP_SCRAPES], total[OT_COUNTER_UDP_CONNID_MISSMATCH]);
  fmt_append(reply, reply_end, "    <livesync>\n      <count>%llu</count>\n    </livesync>\n", total[OT_COUNTER_SYNCS]);
  fmt_append(reply, reply_end, "  </connections>\n");
  fmt_append(reply, reply_end, "  <debug>\n");
  fmt_append(reply, reply_end, "    <renew>\n");
  for (i = 0; i < OT_PEER_TIMEOUT; ++i)
    fmt_append(reply, reply_end, "      <count interval=\"%02i\">%llu</count>\n", i, total[OT_COUNTER_RENEWED + i]);
  fmt_append(reply, reply_end, "    </renew>\n");
  fmt_append(reply, reply_end, "    <http_error>\n");
  for (i = 0; i < CODE_HTTPERROR_COUNT; ++i)
    fmt_append(reply, reply_end, "      <count code=\"%s\">%llu</count>\n", ot_failed_request_names[i],
               total[OT_COUNTER_FAILED + i]);
  fmt_append(reply, reply_end, "    </http_error>\n");
  fmt_append(reply, reply_end, "    <mutex_stall>\n      <count>%llu</count>\n    </mutex_stall>\n",
             total[OT_COUNTER_STALLS]);
  fmt_append(reply, reply_end, "  </debug>\n");
  fmt_append(reply, reply_end, "</stats>");
}

static const char *const build_features[] = {
#ifdef WANT_V4_ONLY
    "WANT_V4_ONLY",
#endif
#ifdef WANT_ACCESSLIST_BLACK
    "WANT_ACCESSLIST_BLACK",
#endif
#ifdef WANT_ACCESSLIST_WHITE
    "WANT_ACCESSLIST_WHITE",
#endif
#ifdef WANT_DYNAMIC_ACCESSLIST
    "WANT_DYNAMIC_ACCESSLIST",
#endif
#ifdef WANT_SYNC_LIVE
    "WANT_SYNC_LIVE",
#endif
#ifdef WANT_IP_FROM_QUERY_STRING
    "WANT_IP_FROM_QUERY_STRING",
#endif
#ifdef WANT_IP_FROM_PROXY
    "WANT_IP_FROM_PROXY",
#endif
#ifdef WANT_COMPRESSION_GZIP
    "WANT_COMPRESSION_GZIP",
#endif
#ifdef WANT_COMPRESSION_GZIP_ALWAYS
    "WANT_COMPRESSION_GZIP_ALWAYS",
#endif
#ifdef WANT_COMPRESSION_ZSTD
    "WANT_COMPRESSION_ZSTD",
#endif
#ifdef WANT_COMPRESSION_ZSTD_ALWAYS
    "WANT_COMPRESSION_ZSTD_ALWAYS",
#endif
#ifdef WANT_FULLSCRAPE
    "WANT_FULLSCRAPE",
#endif
#ifdef WANT_MODEST_FULLSCRAPES
    "WANT_MODEST_FULLSCRAPES",
#endif
#ifdef WANT_KEEPALIVE
    "WANT_KEEPALIVE",
#endif
#ifdef WANT_RESTRICT_STATS
    "WANT_RESTRICT_STATS",
#endif
#ifdef WANT_RESTRICT_FULLSCRAPE
    "WANT_RESTRICT_FULLSCRAPE",
#endif
#ifdef WANT_LOG_NUMWANT
    "WANT_LOG_NUMWANT",
#endif
#ifdef WANT_SPOT_WOODPECKER
    "WANT_SPOT_WOODPECKER",
#endif
#ifdef WANT_SYSLOGS
    "WANT_SYSLOGS",
#endif
#ifdef WANT_DEV_RANDOM
    "WANT_DEV_RANDOM",
#endif
#ifdef WANT_INSECURE_RANDOM_FALLBACK
    "WANT_INSECURE_RANDOM_FALLBACK",
#endif
    NULL};

void stats_return_tracker_features(char **reply, const char *reply_end) {
  size_t i;

  fmt_append(reply, reply_end, "events: %s\n", event_mechanism());
  fmt_append(reply, reply_end, "features:");
  for (i = 0; build_features[i]; ++i)
    fmt_append(reply, reply_end, " %s", build_features[i]);
  if (!build_features[0])
    fmt_append(reply, reply_end, " none");
  fmt_append(reply, reply_end, "\n");
}

void stats_return_tracker_version(char **reply, const char *reply_end) {
  fmt_append(reply, reply_end, "YukiTracker %s\n", TRACKER_VERSION);
}

void return_stats_for_tracker(char **reply, const char *reply_end, int mode, int format) {
  (void)format;
  switch (mode & TASK_TASK_MASK) {
  case TASK_STATS_CONNS:
    stats_connections_mrtg(reply, reply_end);
    break;
  case TASK_STATS_SCRAPE:
    stats_scrape_mrtg(reply, reply_end);
    break;
  case TASK_STATS_UDP:
    stats_udpconnections_mrtg(reply, reply_end);
    break;
  case TASK_STATS_TCP:
    stats_tcpconnections_mrtg(reply, reply_end);
    break;
  case TASK_STATS_FULLSCRAPE:
    stats_fullscrapes_mrtg(reply, reply_end);
    break;
  case TASK_STATS_COMPLETED:
    stats_return_completed_mrtg(reply, reply_end);
    break;
  case TASK_STATS_HTTPERRORS:
    stats_httperrors_txt(reply, reply_end);
    break;
  case TASK_STATS_RENEW:
    stats_return_renew_bucket(reply, reply_end);
    break;
  case TASK_STATS_SYNCS:
    stats_return_sync_mrtg(reply, reply_end);
    break;
#ifdef WANT_LOG_NUMWANT
  case TASK_STATS_NUMWANTS:
    stats_return_numwants(reply, reply_end);
    break;
#endif
  default:
    break;
  }
}

static void render_tracker_summary(char **out, const char *end, int json) {
  unsigned long long totals[OT_COUNTER_COUNT];
  ot_swarm_counts counts;
  counters_total(totals);
  mutex_swarm_counts(&counts);
  size_t torrents = counts.torrents, v4 = counts.ipv4, v6 = counts.ipv6, seeds = counts.seeders;
  unsigned long long completed = counts.completed;
  size_t leeches = v4 + v6 - seeds;
  long long up = time_since_seconds(ot_start_time);
  if (json) {
    fmt_append(out, end,
               "{\"service\":\"YukiTracker\",\"version\":\"" TRACKER_VERSION "\",\"uptime_seconds\":%lld,"
               "\"torrents\":%zu,\"peers\":{\"total\":%zu,\"seeders\":%zu,\"leechers\":%zu},"
               "\"peers_by_family\":{\"ipv4\":%zu,\"ipv6\":%zu},\"completions\":%llu,"
               "\"requests\":{\"announce\":%llu,\"scrape\":%llu,\"export\":%llu},"
               "\"udp\":{\"connect\":%llu,\"announce\":%llu,\"scrape\":%llu}}\n",
               up, torrents, v4 + v6, seeds, leeches, v4, v6, completed, totals[OT_COUNTER_TCP_ANNOUNCES],
               totals[OT_COUNTER_TCP_SCRAPES], totals[OT_COUNTER_EXPORT], totals[OT_COUNTER_UDP_CONNECTS],
               totals[OT_COUNTER_UDP_ANNOUNCES], totals[OT_COUNTER_UDP_SCRAPES]);
  } else {
    fmt_append(out, end,
               "yukitracker_uptime_seconds %lld\nyukitracker_torrents %zu\n"
               "yukitracker_peers{role=\"seeder\"} %zu\nyukitracker_peers{role=\"leecher\"} %zu\n"
               "yukitracker_completions_total %llu\nyukitracker_build_info{version=\"" TRACKER_VERSION "\"} 1\n"
               "yukitracker_peers_by_family{family=\"ipv4\"} %zu\nyukitracker_peers_by_family{family=\"ipv6\"} %zu\n",
               up, torrents, seeds, leeches, completed, v4, v6);
    static const struct {
      const char *proto, *kind;
      unsigned index;
    } counters[] = {{"http", "announce", OT_COUNTER_TCP_ANNOUNCES}, {"http", "scrape", OT_COUNTER_TCP_SCRAPES},
                    {"http", "export", OT_COUNTER_EXPORT},          {"udp", "connect", OT_COUNTER_UDP_CONNECTS},
                    {"udp", "announce", OT_COUNTER_UDP_ANNOUNCES},  {"udp", "scrape", OT_COUNTER_UDP_SCRAPES}};
    for (size_t i = 0; i < sizeof(counters) / sizeof(*counters); ++i)
      fmt_append(out, end, "yukitracker_requests_total{proto=\"%s\",kind=\"%s\"} %llu\n", counters[i].proto,
                 counters[i].kind, totals[counters[i].index]);
  }
}

static void stats_make(size_t *iovec_entries, struct iovec **iovector, ot_tasktype mode) {
  char *r;
  const char *r_end;

  *iovec_entries = 0;
  *iovector = NULL;
  if (!(r = iovec_new_chunk(iovec_entries, iovector, OT_STATS_TMPSIZE)))
    return;
  r_end = r + OT_STATS_TMPSIZE;

  switch (mode & TASK_TASK_MASK) {
  case TASK_STATS_JSON:
  case TASK_STATS_METRICS:
    render_tracker_summary(&r, r_end, mode == TASK_STATS_JSON);
    break;
  case TASK_STATS_TORRENTS:
    stats_torrents_mrtg(&r, r_end);
    break;
  case TASK_STATS_PEERS:
    stats_peers_mrtg(&r, r_end);
    break;
  case TASK_STATS_TOP10:
    stats_top_txt(&r, r_end, 10);
    break;
  case TASK_STATS_TOP100:
    r = iovec_next_chunk(iovec_entries, iovector, r, 4 * OT_STATS_TMPSIZE);
    if (!r)
      return;
    r_end = r + 4 * OT_STATS_TMPSIZE;
    stats_top_txt(&r, r_end, 100);
    break;
  case TASK_STATS_EVERYTHING:
    r = iovec_next_chunk(iovec_entries, iovector, r, OT_STATS_TMPSIZE + 64 * OT_PEER_TIMEOUT);
    if (!r)
      return;
    r_end = r + OT_STATS_TMPSIZE + 64 * OT_PEER_TIMEOUT;
    stats_return_everything(&r, r_end);
    break;
#ifdef WANT_SPOT_WOODPECKER
  case TASK_STATS_WOODPECKERS:
    stats_return_woodpeckers(&r, r_end, 128);
    break;
#endif
  default:
    iovec_free(iovec_entries, iovector);
    return;
  }
  iovec_trim_last(iovec_entries, iovector, r);
}

void stats_issue_event(struct ot_workstruct *ws, ot_status_event event, PROTO_FLAG proto, uintptr_t event_data) {
  if (!ws)
    return;

  switch (event) {
  case EVENT_ACCEPT:
    if (proto == FLAG_TCP)
      COUNT(OT_COUNTER_TCP_CONNECTIONS, 1);
    else
      COUNT(OT_COUNTER_UDP_CONNECTIONS, 1);
    break;
  case EVENT_ANNOUNCE:
    if (proto == FLAG_TCP)
      COUNT(OT_COUNTER_TCP_ANNOUNCES, 1);
    else
      COUNT(OT_COUNTER_UDP_ANNOUNCES, 1);
    break;
  case EVENT_CONNECT:
    if (proto == FLAG_TCP)
      COUNT(OT_COUNTER_TCP_CONNECTS, 1);
    else
      COUNT(OT_COUNTER_UDP_CONNECTS, 1);
    break;
  case EVENT_COMPLETED:
#ifdef WANT_SYSLOGS
  {
    char timestring[64];
    char hash_hex[42], peerid_hex[42], ip_readable[64];
    struct tm time_now;
    time_t ttt;

    time(&ttt);
    localtime_r(&ttt, &time_now);
    if (!strftime(timestring, sizeof(timestring), "%FT%T%z", &time_now))
      timestring[0] = 0;

    hex_from_hash(hash_hex, *ws->hash);
    if (ws->peer_id)
      hex_from_hash(peerid_hex, (uint8_t *)ws->peer_id);
    else {
      *peerid_hex = 0;
    }

    ip_readable[ip_format(ip_readable, (char *)&ws->peer)] = 0;
    syslog(LOG_INFO, "time=%s event=completed info_hash=%s peer_id=%s ip=%s", timestring, hash_hex, peerid_hex,
           ip_readable);
  }
#endif
    COUNT(OT_COUNTER_COMPLETED, 1);
    break;
  case EVENT_SCRAPE:
    if (proto == FLAG_TCP)
      COUNT(OT_COUNTER_TCP_SCRAPES, 1);
    else
      COUNT(OT_COUNTER_UDP_SCRAPES, 1);
    break;
  case EVENT_FULLSCRAPE:
    COUNT(OT_COUNTER_FULLSCRAPES, 1);
    COUNT(OT_COUNTER_FULLSCRAPE_BYTES, event_data);
    break;
  case EVENT_FULLSCRAPE_REQUEST: {
    ot_ip6 *ip = (ot_ip6 *)event_data;
    char _debug[512];
    int off = snprintf(_debug, sizeof(_debug), "[%08d] scrp:  ", (unsigned int)time_since_seconds(ot_start_time) / 60);
    off += ip_format(_debug + off, *ip);
    off += snprintf(_debug + off, sizeof(_debug) - off, " - FULL SCRAPE\n");
    (void)!write(2, _debug, off);
    COUNT(OT_COUNTER_FULLSCRAPE_REQUESTS, 1);
  } break;
  case EVENT_FULLSCRAPE_REQUEST_GZIP: {
    ot_ip6 *ip = (ot_ip6 *)event_data;
    char _debug[512];
    int off = snprintf(_debug, sizeof(_debug), "[%08d] scrp:  ", (unsigned int)time_since_seconds(ot_start_time) / 60);
    off += ip_format(_debug + off, *ip);
    off += snprintf(_debug + off, sizeof(_debug) - off, " - FULL SCRAPE\n");
    (void)!write(2, _debug, off);
    COUNT(OT_COUNTER_FULLSCRAPE_REQUESTS, 1);
  } break;
  case EVENT_FAILED:
    if (event_data < CODE_HTTPERROR_COUNT)
      COUNT(OT_COUNTER_FAILED + event_data, 1);
    break;
  case EVENT_RENEW:
    if (event_data < (uintptr_t)OT_PEER_TIMEOUT)
      COUNT(OT_COUNTER_RENEWED + event_data, 1);
    break;
  case EVENT_SYNC:
    COUNT(OT_COUNTER_SYNCS, event_data);
    break;
  case EVENT_BUCKET_LOCKED:
    COUNT(OT_COUNTER_STALLS, 1);
    break;
#ifdef WANT_SPOT_WOODPECKER
  case EVENT_WOODPECKER:
    pthread_mutex_lock(&g_woodpeckers_mutex);
    stat_increase_network_count(&stats_woodpeckers_tree, 0, event_data);
    pthread_mutex_unlock(&g_woodpeckers_mutex);
    break;
#endif
  case EVENT_CONNID_MISSMATCH:
    COUNT(OT_COUNTER_UDP_CONNID_MISSMATCH, 1);
  default:
    break;
  }
}

void stats_cleanup(void) {
#ifdef WANT_SPOT_WOODPECKER
  pthread_mutex_lock(&g_woodpeckers_mutex);
  stats_shift_down_network_count(&stats_woodpeckers_tree, 0, 1);
  pthread_mutex_unlock(&g_woodpeckers_mutex);
#endif
}

static void *stats_worker(void *args) {
  size_t iovec_entries;
  struct iovec *iovector;

  (void)args;

  while (tracker_running) {
    ot_tasktype tasktype = TASK_STATS;
    struct catalog_query query;
    ot_taskid taskid = workqueue_popquery(&tasktype, &query);
    if (!taskid)
      break;
    if (tasktype == TASK_STATS_CATALOG) {
      iovec_entries = 0;
      iovector = NULL;
      size_t cap = (query.kind == CATALOG_LOG ? 3328 : 256) * (size_t)query.limit + 128;
      char *out = iovec_new_chunk(&iovec_entries, &iovector, cap);
      if (out) {
        size_t size = catalog_render(out, cap, &query);
        if (size)
          iovec_trim_last(&iovec_entries, &iovector, out + size);
        else
          iovec_free(&iovec_entries, &iovector);
      }
    } else
      stats_make(&iovec_entries, &iovector, tasktype);
    if (workqueue_pushresult(taskid, iovec_entries, iovector))
      iovec_free(&iovec_entries, &iovector);
  }
  return NULL;
}

void stats_deliver(int64_t sock, int tasktype) { workqueue_pushtask(sock, tasktype); }

static pthread_t thread_id;
void stats_init(void) {
  ot_start_time = time_now_seconds();
  pthread_create(&thread_id, NULL, stats_worker, NULL);
}

void stats_deinit(void) {
  workqueue_wakeall();
  pthread_join(thread_id, NULL);
}

/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_TRACKERLOGIC_H__
#define OT_TRACKERLOGIC_H__

#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

typedef uint8_t ot_hash[20];
typedef time_t ot_time;
typedef char ot_ip6[16];
typedef struct {
  ot_ip6 address;
  int bits;
} ot_net;

#define OT_MAX_PEERS_UDP6 66
#define OT_MAX_PEERS_UDP4 200

#define OT_IP_SIZE6 16
#define OT_IP_SIZE4 4
#define OT_PORT_SIZE 2
#define OT_FLAG_SIZE 1
#define OT_TIME_SIZE 1

#ifndef OT_CLIENT_TIMEOUT
#define OT_CLIENT_TIMEOUT 30
#endif
#ifndef OT_CLIENT_TIMEOUT_CHECKINTERVAL
#define OT_CLIENT_TIMEOUT_CHECKINTERVAL 10
#endif
extern int g_http_read_timeout, g_http_write_timeout;
extern int g_announce_interval, g_announce_jitter, g_default_numwant, g_max_http, g_max_udp4, g_max_udp6, g_keepalive;
#define OT_CLIENT_REQUEST_VARIATION (60 * 6)
#define OT_CLIENT_REJECT_INTERVAL (60 * 120)

#define OT_TORRENT_TIMEOUT_HOURS 24
#define OT_TORRENT_TIMEOUT (60 * OT_TORRENT_TIMEOUT_HOURS)

extern ot_time g_empty_torrent_timeout;

#define OT_CLIENT_REQUEST_INTERVAL_RANDOM                                                                              \
  (g_announce_interval - g_announce_jitter / 2 +                                                                       \
   (g_announce_jitter ? (int)(nrand48(ws->rand48_state) % g_announce_jitter) : 0))
#define OT_CLIENT_REJECT_INTERVAL_RANDOM                                                                               \
  (OT_CLIENT_REJECT_INTERVAL - OT_CLIENT_REQUEST_VARIATION / 2 +                                                       \
   (int)(nrand48(ws->rand48_state) % OT_CLIENT_REQUEST_VARIATION))

#define OT_MODEST_PEER_TIMEOUT (60 * 5)

#define OT_CLIENT_SYNC_RENEW_BOUNDARY 10

#define OT_ADMINIP_MAX 64
#define OT_MAX_THREADS 64

extern int g_max_scrape_http, g_max_scrape_udp, g_key_minutes;
extern double g_min_ratio;
extern int g_peer_timeout, g_torrent_timeout;
#define OT_PEER_TIMEOUT g_peer_timeout

#ifndef OT_BUCKET_COUNT_BITS
#define OT_BUCKET_COUNT_BITS 10
#endif

#define OT_BUCKET_COUNT (1 << OT_BUCKET_COUNT_BITS)
#define OT_BUCKET_COUNT_SHIFT (32 - OT_BUCKET_COUNT_BITS)

#if defined(CLOCK_MONOTONIC_COARSE)
#define OT_CLOCK_CHEAP CLOCK_MONOTONIC_COARSE
#elif defined(CLOCK_MONOTONIC_FAST)
#define OT_CLOCK_CHEAP CLOCK_MONOTONIC_FAST
#else
#define OT_CLOCK_CHEAP CLOCK_MONOTONIC
#endif

static inline ot_time time_now_seconds(void) {
  struct timespec now;
  clock_gettime(OT_CLOCK_CHEAP, &now);
  return (ot_time)now.tv_sec;
}

static inline ot_time time_now_minutes(void) { return time_now_seconds() / 60; }

static inline ot_time time_future_seconds(int span) { return time_now_seconds() + span; }

_Static_assert((ot_time)-1 < 0, "ot_time has to be signed for time_since_* to clamp");

static inline ot_time time_since_seconds(ot_time then) {
  ot_time now = time_now_seconds();
  return now > then ? now - then : 0;
}

static inline ot_time time_since_minutes(ot_time then) {
  ot_time now = time_now_minutes();
  return now > then ? now - then : 0;
}

static inline int time_is_past(ot_time deadline) { return time_now_seconds() > deadline; }

static inline ot_time time_wall_minutes(void) { return time(NULL) / 60; }

extern _Atomic int tracker_running;

#define OT_SIGNAL_WAKE SIGUSR1

extern uint32_t g_tracker_id;
typedef enum { FLAG_TCP, FLAG_UDP, FLAG_MCA, FLAG_SELFPIPE } PROTO_FLAG;

#define OT_PEER_COMPARE_SIZE6 ((OT_IP_SIZE6) + (OT_PORT_SIZE))
#define OT_PEER_COMPARE_SIZE4 ((OT_IP_SIZE4) + (OT_PORT_SIZE))
#define OT_PEER_COMPARE_SIZE_FROM_PEER_SIZE(PEER_SIZE) ((PEER_SIZE) - (OT_TIME_SIZE) - (OT_FLAG_SIZE))

#define OT_PEER_SIZE6 ((OT_TIME_SIZE) + (OT_FLAG_SIZE) + (OT_PEER_COMPARE_SIZE6))
#define OT_PEER_SIZE4 ((OT_TIME_SIZE) + (OT_FLAG_SIZE) + (OT_PEER_COMPARE_SIZE4))

typedef uint8_t ot_peer;
typedef uint8_t ot_peer6[OT_PEER_SIZE6];
typedef uint8_t ot_peer4[OT_PEER_SIZE4];
static const uint8_t PEER_FLAG_SEEDING = 0x80;
static const uint8_t PEER_FLAG_COMPLETED = 0x40;
static const uint8_t PEER_FLAG_STOPPED = 0x20;
static const uint8_t PEER_FLAG_FROM_SYNC = 0x10;
static const uint8_t PEER_FLAG_LEECHING = 0x00;

ot_peer *peer_from_peer6(ot_peer6 *peer, size_t *peer_size);
size_t peer_size_from_peer6(ot_peer6 *peer);

#define OT_SETIP(peer, ip) memcpy((uint8_t *)(peer), (ip), OT_IP_SIZE6)
#define OT_SETPORT(peer, port) memcpy(((uint8_t *)(peer)) + (OT_IP_SIZE6), (port), 2)
#define OT_PEERFLAG(peer) (((uint8_t *)(peer))[(OT_IP_SIZE6) + 2])
#define OT_PEERFLAG_D(peer, peersize) (((uint8_t *)(peer))[(peersize) - 2])
#define OT_PEERTIME(peer, peersize) (((uint8_t *)(peer))[(peersize) - 1])

#define PEERS_BENCODED6 "6:peers6"
#define PEERS_BENCODED4 "5:peers"

#define OT_HASH_COMPARE_SIZE (sizeof(ot_hash))

struct ot_peerlist;
typedef struct ot_peerlist ot_peerlist;
typedef struct {
  ot_hash hash;
  ot_peerlist *peer_list;
  uint32_t base;
  uint32_t down_count;
} ot_torrent;

#include "ot_vector.h"

struct ot_peerlist {
  uint32_t seed_count;

  ot_vector peers6;
  ot_vector peers4;
};

#define OT_VECTOR_HASBUCKETS(v) ((v)->size > (v)->space)

static inline size_t vector_peer_count(const ot_vector *v) {
  const ot_vector *b;
  size_t n, total = 0;
  if (!OT_VECTOR_HASBUCKETS(v))
    return v->size;
  b = (const ot_vector *)v->data;
  for (n = 0; n < v->size; ++n)
    total += b[n].size;
  return total;
}
static inline size_t torrent_peer_count(const ot_torrent *t) {
  return t->peer_list ? vector_peer_count(&t->peer_list->peers6) + vector_peer_count(&t->peer_list->peers4) : 0;
}
static inline uint32_t torrent_seed_count(const ot_torrent *t) { return t->peer_list ? t->peer_list->seed_count : 0; }

enum {
  CODE_HTTPERROR_302,
  CODE_HTTPERROR_400,
  CODE_HTTPERROR_400_PARAM,
  CODE_HTTPERROR_400_COMPACT,
  CODE_HTTPERROR_402_NOTMODEST,
  CODE_HTTPERROR_402_PAYMENT_REQUIRED,
  CODE_HTTPERROR_403_IP,
  CODE_HTTPERROR_404,
  CODE_HTTPERROR_500,

  CODE_HTTPERROR_COUNT
};

typedef _Atomic unsigned long long ot_counter;

typedef enum {
  OT_COUNTER_TCP_CONNECTIONS,
  OT_COUNTER_UDP_CONNECTIONS,
  OT_COUNTER_TCP_ANNOUNCES,
  OT_COUNTER_UDP_ANNOUNCES,
  OT_COUNTER_TCP_SCRAPES,
  OT_COUNTER_UDP_SCRAPES,
  OT_COUNTER_TCP_CONNECTS,
  OT_COUNTER_UDP_CONNECTS,
  OT_COUNTER_UDP_CONNID_MISSMATCH,
  OT_COUNTER_COMPLETED,
  OT_COUNTER_EXPORT,
  OT_COUNTER_FULLSCRAPES,
  OT_COUNTER_FULLSCRAPE_REQUESTS,
  OT_COUNTER_FULLSCRAPE_BYTES,
  OT_COUNTER_SYNCS,
  OT_COUNTER_STALLS,

  OT_COUNTER_FAILED,
  OT_COUNTER_RENEWED = OT_COUNTER_FAILED + CODE_HTTPERROR_COUNT,

  OT_COUNTER_COUNT = OT_COUNTER_RENEWED + 255
} ot_counter_index;

struct ot_workstruct {

  ot_counter counters[OT_COUNTER_COUNT];
  struct ot_workstruct *counters_next;

  char *inbuf;
#define G_INBUF_SIZE 8192
  char *outbuf;
#define G_OUTBUF_SIZE 8192

  ot_peer6 peer;

  ot_hash *hash;
  char *peer_id;

  char *request;
  ssize_t request_size;
  ssize_t header_size;
  char *reply;
  ssize_t reply_size;

  uint16_t rand48_state[3];

  int keep_alive;

  int handed_off;
};

int workstruct_init(struct ot_workstruct *ws, size_t inbuf_size);
void workstruct_deinit(struct ot_workstruct *ws);

#ifdef WANT_SYNC_LIVE
#define WANT_SYNC
#endif

#ifdef WANT_SYNC
#define WANT_SYNC_PARAM(param) , param
#else
#define WANT_SYNC_PARAM(param)
#endif

void trackerlogic_init(void);
void trackerlogic_deinit(void);
void exerr(const char *message);

size_t add_peer_to_torrent_and_return_peers(PROTO_FLAG proto, struct ot_workstruct *ws, size_t amount);
size_t remove_peer_from_torrent(PROTO_FLAG proto, struct ot_workstruct *ws);
void return_tcp_scrape_for_torrent(ot_hash const *hash_list, size_t amount, char **reply, const char *reply_end);
size_t return_udp_scrape_for_torrent(ot_hash const hash, char *reply);
void add_torrent_from_saved_state(ot_hash const hash, ot_time age, size_t down_count);

void iterate_all_torrents(int (*for_each)(ot_torrent *torrent, uintptr_t data), uintptr_t data);

void free_peerlist(ot_peerlist *peer_list);
void free_peer_vector(ot_vector *peer_vector);

#endif

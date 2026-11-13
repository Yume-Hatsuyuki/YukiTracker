/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#include "ot_accesslist.h"
#include "ot_fullscrape.h"
#include "ot_http.h"
#include "ot_config.h"
#include "diagnostics.h"
#include "ot_iovec.h"
#include "ot_ip.h"
#include "ot_random.h"
#include "ot_mutex.h"
#include "ot_workqueue.h"
#include "ot_scan.h"
#include "ot_event.h"
#include "ot_fdstate.h"
#include "ot_vector.h"
#include "ot_fmt.h"
#include "ot_stats.h"
#include "ot_urlencoded.h"
#include "trackerlogic.h"

#define OT_MAXMULTISCRAPE_COUNT 64
extern const char *g_redirecturl;

const char *g_stats_path;
ssize_t g_stats_path_len;

enum { SUCCESS_HTTP_HEADER_LENGTH = 80, SUCCESS_HTTP_SIZE_OFF = 17 };

struct http_data *http_adopt(const int64_t sock) {
  struct http_data *cookie = fdstate_cookie(sock), *heap;
  int interest;

  if (!cookie || !(cookie->flag & STRUCT_HTTP_FLAG_ONSTACK))
    return cookie;

  if (!(heap = malloc(sizeof(*heap))))
    return NULL;

  *heap = *cookie;
  heap->flag &= ~STRUCT_HTTP_FLAG_ONSTACK;

  interest = heap->interest;
  fdstate_set_cookie((int)sock, heap);

  if (event_add((int)sock, interest, fdstate_generation((int)sock)) == -1) {
    fdstate_set_cookie((int)sock, cookie);
    free(heap);
    return NULL;
  }
  return heap;
}

void http_close(const int64_t sock) {
  struct http_data *cookie = fdstate_cookie(sock);

  fdstate_close((int)sock);

  if (cookie) {
    if (cookie->batch)
      batch_reset(cookie->batch);
    free(cookie->batch);
    buf_reset(&cookie->request);
    if (cookie->flag & (STRUCT_HTTP_FLAG_WAITINGFORTASK | STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER))
      workqueue_canceltask(sock);
    if (!(cookie->flag & STRUCT_HTTP_FLAG_ONSTACK))
      free(cookie);
  }

  event_close((int)sock);
}

static void http_senddata(const int64_t sock, struct ot_workstruct *ws) {
  struct http_data *cookie = fdstate_cookie(sock);
  ssize_t written_size;

  if (!cookie) {
    http_close(sock);
    return;
  }

  if (ws->keep_alive && ws->header_size != ws->request_size) {
    size_t rest = ws->request_size - ws->header_size;
    if (cookie->request.data) {
      memmove(cookie->request.data, ws->request + ws->header_size, rest);
      buf_truncate(&cookie->request, rest);
    } else if (buf_cat(&cookie->request, ws->request + ws->header_size, rest)) {

      buf_reset(&cookie->request);
      ws->keep_alive = 0;
    }
  } else
    buf_reset(&cookie->request);

  written_size = write(sock, ws->reply, ws->reply_size);

  if (written_size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    written_size = 0;

  if ((written_size < 0) || ((written_size == ws->reply_size) && !ws->keep_alive)) {
    http_close(sock);
    return;
  }

  if (written_size < ws->reply_size) {
    char *outbuf;

    if (!(outbuf = malloc(ws->reply_size - written_size))) {
      http_close(sock);
      return;
    }

    memcpy(outbuf, ws->reply + written_size, ws->reply_size - written_size);
    if (!cookie->batch) {
      cookie->batch = calloc(1, sizeof(ot_batch));
      if (!cookie->batch) {
        free(outbuf);
        http_close(sock);
        return;
      }
    }

    batch_add(cookie->batch, outbuf, ws->reply_size - written_size);

    fdstate_set_expiry(sock, time_future_seconds(g_http_write_timeout));
    http_interest_set(sock, cookie, EVENT_OUT);
  }
}

#define HTTPERROR_302 return http_issue_error(sock, ws, CODE_HTTPERROR_302)
#define HTTPERROR_400 return http_issue_error(sock, ws, CODE_HTTPERROR_400)
#define HTTPERROR_400_PARAM return http_issue_error(sock, ws, CODE_HTTPERROR_400_PARAM)
#define HTTPERROR_400_COMPACT return http_issue_error(sock, ws, CODE_HTTPERROR_400_COMPACT)
#define HTTPERROR_400_DOUBLEHASH return http_issue_error(sock, ws, CODE_HTTPERROR_400_PARAM)
#define HTTPERROR_402_NOTMODEST return http_issue_error(sock, ws, CODE_HTTPERROR_402_NOTMODEST)
#define HTTPERROR_403_IP return http_issue_error(sock, ws, CODE_HTTPERROR_403_IP)
#define HTTPERROR_404 return http_issue_error(sock, ws, CODE_HTTPERROR_404)
#define HTTPERROR_500 return http_issue_error(sock, ws, CODE_HTTPERROR_500)

void http_interest_set(const int64_t sock, struct http_data *cookie, int what) {
  if (cookie->interest == what)
    return;
  cookie->interest = what;

  if (cookie->flag & STRUCT_HTTP_FLAG_ONSTACK)
    return;
  event_modify((int)sock, what, fdstate_generation((int)sock));
}

ssize_t http_issue_error(const int64_t sock, struct ot_workstruct *ws, int code) {
  const char *error_code[] = {"302 Found",           "400 Invalid Request",  "400 Invalid Request",
                              "400 Invalid Request", "402 Payment Required", "403 Not Modest",
                              "403 Access Denied",   "404 Not Found",        "500 Internal Server Error"};
  const char *title = error_code[code];

  ws->reply = ws->outbuf;
  if (code == CODE_HTTPERROR_302)
    ws->reply_size = snprintf(ws->reply, G_OUTBUF_SIZE,
                              "HTTP/1.0 302 Found\r\nContent-Length: 0\r\nLocation: %s\r\n\r\n", g_redirecturl);
  else
    ws->reply_size =
        snprintf(ws->reply, G_OUTBUF_SIZE,
                 "HTTP/1.0 %s\r\nContent-Type: text/html\r\nContent-Length: %zd\r\n\r\n<title>%s</title>\n", title,
                 strlen(title) + 16 - 4, title + 4);

  stats_issue_event(ws, EVENT_FAILED, FLAG_TCP, code);
  http_senddata(sock, ws);
  return ws->reply_size = -2;
}

ssize_t http_sendiovecdata(const int64_t sock, struct ot_workstruct *ws, size_t iovec_entries, struct iovec *iovector,
                           int is_partial) {
  struct http_data *cookie = fdstate_cookie(sock);
  char *header;
  const char *encoding = "";
  size_t header_size, size = iovec_length(&iovec_entries, (const struct iovec **)&iovector);

  if (!cookie) {
    iovec_free(&iovec_entries, &iovector);
    HTTPERROR_500;
  }

  if (!(cookie->flag & (STRUCT_HTTP_FLAG_WAITINGFORTASK | STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER))) {
    iovec_free(&iovec_entries, &iovector);
    return 0;
  }

  buf_reset(&cookie->request);

  if (cookie->flag & STRUCT_HTTP_FLAG_WAITINGFORTASK) {
    http_interest_set(sock, cookie, 0);
    cookie->flag &= ~STRUCT_HTTP_FLAG_WAITINGFORTASK;
  }

  if (iovec_entries && !size && (cookie->flag & STRUCT_HTTP_FLAG_NDJSON) &&
      !(cookie->flag & STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER)) {
    iovec_free(&iovec_entries, &iovector);
    ws->reply = ws->outbuf;
    ws->reply_size = snprintf(ws->outbuf, G_OUTBUF_SIZE,
                              "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: 0\r\n\r\n");
    ws->keep_alive = 0;
    http_senddata(sock, ws);
    return 0;
  }
  if (iovec_entries) {

    if (cookie->flag & STRUCT_HTTP_FLAG_ZSTD)
      encoding = "Content-Encoding: zstd\r\n";
    else if (cookie->flag & STRUCT_HTTP_FLAG_GZIP)
      encoding = "Content-Encoding: gzip\r\n";
    else if (cookie->flag & STRUCT_HTTP_FLAG_BZIP2)
      encoding = "Content-Encoding: bzip2\r\n";

    if (!(cookie->flag & STRUCT_HTTP_FLAG_CHUNKED))
      header_size = asprintf(&header, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n%sContent-Length: %zd\r\n\r\n",
                             cookie->flag & STRUCT_HTTP_FLAG_JSON ? "application/json" : "text/plain", encoding, size);
    else {
      if (!(cookie->flag & STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER)) {
        header_size =
            asprintf(&header, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n%sTransfer-Encoding: chunked\r\n\r\n%zx\r\n",
                     cookie->flag & STRUCT_HTTP_FLAG_NDJSON ? "application/x-ndjson" : "application/octet-stream",
                     encoding, size);
        cookie->flag |= STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER;
      } else
        header_size = asprintf(&header, "%zx\r\n", size);
    }
    if (!header) {
      iovec_free(&iovec_entries, &iovector);
      HTTPERROR_500;
    }

    if (!cookie->batch) {
      cookie->batch = calloc(1, sizeof(ot_batch));
      if (!cookie->batch) {
        free(header);
        iovec_free(&iovec_entries, &iovector);
        HTTPERROR_500;
      }
    }

    batch_add(cookie->batch, header, header_size);
    batch_add_vector(cookie->batch, iovector, iovec_entries);
    free(iovector);

    if (cookie->flag & STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER)
      batch_add_copy(cookie->batch, "\r\n", 2);
  }

  if ((cookie->flag & STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER) && cookie->batch && !is_partial) {
    batch_add_copy(cookie->batch, "0\r\n\r\n", 5);
    cookie->flag &= ~STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER;
  }

  fdstate_set_expiry(sock, time_future_seconds(g_http_write_timeout));
  http_interest_set(sock, cookie, EVENT_OUT);
  return 0;
}

static void api_ip(const struct http_data *client, struct ot_workstruct *ws, ot_ip6 ip);
static char *http_header(char *data, size_t byte_count, const char *header);
static int accepts_gzip(struct ot_workstruct *ws) {
  const char *p = http_header(ws->request, ws->header_size, "accept-encoding");
  if (!p || !g_gzip)
    return 0;
  const char *end = ws->request + ws->header_size;
  while (p < end && *p != '\r' && *p != '\n') {
    while (p < end && (*p == ' ' || *p == '\t' || *p == ','))
      ++p;
    const char *token = p;
    while (p < end && *p != ',' && *p != ';' && !isspace((unsigned char)*p))
      ++p;
    int match = (p - token == 4 && !strncasecmp(token, "gzip", 4));
    while (p < end && (*p == ' ' || *p == '\t'))
      ++p;
    int enabled = 1;
    if (p < end && *p == ';') {
      ++p;
      while (p < end && (*p == ' ' || *p == '\t'))
        ++p;
      enabled = 0;
      if (end - p >= 3 && !strncasecmp(p, "q=", 2)) {
        p += 2;
        while (p < end && ((*p >= '0' && *p <= '9') || *p == '.')) {
          if (*p >= '1' && *p <= '9')
            enabled = 1;
          ++p;
        }
      }
    }
    if (match)
      return enabled;
    while (p < end && *p != ',' && *p != '\r' && *p != '\n')
      ++p;
  }
  return 0;
}

static ssize_t http_handle_stats(const int64_t sock, struct ot_workstruct *ws, char *read_ptr) {
  static const ot_keywords keywords_main[] = {{"mode", 1}, {"format", 2}, {"info_hash", 3}, {NULL, -3}};
  static const ot_keywords keywords_mode[] = {{"peer", TASK_STATS_PEERS},
                                              {"conn", TASK_STATS_CONNS},
                                              {"scrp", TASK_STATS_SCRAPE},
                                              {"udp4", TASK_STATS_UDP},
                                              {"tcp4", TASK_STATS_TCP},
                                              {"torr", TASK_STATS_TORRENTS},
                                              {"fscr", TASK_STATS_FULLSCRAPE},
                                              {"tpbs", TASK_STATS_TPB},
                                              {"herr", TASK_STATS_HTTPERRORS},
                                              {"completed", TASK_STATS_COMPLETED},
                                              {"top100", TASK_STATS_TOP100},
                                              {"top10", TASK_STATS_TOP10},
                                              {"renew", TASK_STATS_RENEW},
                                              {"syncs", TASK_STATS_SYNCS},
                                              {"everything", TASK_STATS_EVERYTHING},
                                              {"statedump", TASK_FULLSCRAPE_TRACKERSTATE},
                                              {"woodpeckers", TASK_STATS_WOODPECKERS},
#ifdef WANT_LOG_NUMWANT
                                              {"numwants", TASK_STATS_NUMWANTS},
#endif
                                              {NULL, -3}};
  static const ot_keywords keywords_format[] = {
      {"bin", TASK_FULLSCRAPE_TPB_BINARY},      {"ben", TASK_FULLSCRAPE},
      {"url", TASK_FULLSCRAPE_TPB_URLENCODED},  {"txt", TASK_FULLSCRAPE_TPB_ASCII},
      {"txtp", TASK_FULLSCRAPE_TPB_ASCII_PLUS}, {NULL, -3}};

  struct http_data *cookie = fdstate_cookie(sock);
  char *reply;
  int mode = TASK_STATS_PEERS, scanon = 1, format = 0;

  if (!cookie)
    HTTPERROR_500;

  ot_ip6 address;
  api_ip(cookie, ws, address);
#ifdef WANT_RESTRICT_STATS
  if (!accesslist_is_blessed(address, OT_PERMISSION_MAY_STAT))
    HTTPERROR_403_IP;
#endif

  while (scanon) {
    switch (urlencoded_match_keyword(keywords_main, &read_ptr, ws->request + ws->request_size, SCAN_SEARCHPATH_PARAM)) {
    case -2:
      scanon = 0;
      break;
    case -1:
      HTTPERROR_400_PARAM;
    case -3:
      urlencoded_skip_value(&read_ptr);
      break;
    case 1:
      if ((mode = urlencoded_match_keyword(keywords_mode, &read_ptr, ws->request + ws->request_size,
                                           SCAN_SEARCHPATH_VALUE)) <= 0)
        HTTPERROR_400_PARAM;
      break;
    case 2:
      if ((format = urlencoded_match_keyword(keywords_format, &read_ptr, ws->request + ws->request_size,
                                             SCAN_SEARCHPATH_VALUE)) <= 0)
        HTTPERROR_400_PARAM;
      break;
    case 3:
      HTTPERROR_400_PARAM;
    }
  }

#ifdef WANT_FULLSCRAPE
  if (mode == TASK_FULLSCRAPE_TRACKERSTATE) {
    format = mode;
    mode = TASK_STATS_TPB;
  }

  if (mode == TASK_STATS_TPB) {
#ifdef WANT_RESTRICT_FULLSCRAPE
    if (!accesslist_is_blessed(address, OT_PERMISSION_MAY_FULLSCRAPE))
      HTTPERROR_403_IP;
#endif
#ifdef WANT_COMPRESSION_GZIP
    ws->request[ws->request_size - 1] = 0;
#ifndef WANT_COMPRESSION_GZIP_ALWAYS
    if (accepts_gzip(ws)) {
#endif
      cookie->flag |= STRUCT_HTTP_FLAG_GZIP;
      format |= TASK_FLAG_GZIP;
#ifndef WANT_COMPRESSION_GZIP_ALWAYS
    }
#endif
#endif
    cookie->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK | STRUCT_HTTP_FLAG_CHUNKED;

    fdstate_set_expiry(sock, 0);
    http_interest_set(sock, cookie, 0);

    if (!http_adopt(sock))
      HTTPERROR_500;
    ws->handed_off = 1;
    fullscrape_deliver(sock, format);
    return ws->reply_size = -2;
  }
#endif

  if ((mode & TASK_CLASS_MASK) == TASK_STATS) {

    cookie->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;

    fdstate_set_expiry(sock, 0);
    http_interest_set(sock, cookie, 0);

    if (!http_adopt(sock))
      HTTPERROR_500;
    ws->handed_off = 1;
    stats_deliver(sock, mode);
    return ws->reply_size = -2;
  }

  reply = ws->reply;
  return_stats_for_tracker(&reply, ws->outbuf + G_OUTBUF_SIZE, mode, 0);
  return ws->reply_size = reply - ws->reply;
}

#ifdef WANT_MODEST_FULLSCRAPES
static pthread_mutex_t g_modest_fullscrape_mutex = PTHREAD_MUTEX_INITIALIZER;
static ot_vector g_modest_fullscrape_timeouts;
typedef struct {
  ot_ip6 ip;
  ot_time last_fullscrape;
} ot_scrape_log;
#endif

#ifdef WANT_FULLSCRAPE
struct export_client {
  ot_ip6 ip;
  ot_time until;
  unsigned bucket, next, previous;
};
static struct export_client *export_clients;
static unsigned *export_buckets;
static unsigned bucket_mask, hash_seed, first_client, client_count;
static pthread_mutex_t export_lock = PTHREAD_MUTEX_INITIALIZER;

void http_export_init(void) {
  if (!g_export_enabled || !g_export_interval)
    return;
  unsigned buckets = 1;
  while (buckets < g_export_max_clients)
    buckets *= 2;
  bucket_mask = buckets - 1;
  hash_seed = random_uint32();

  export_clients = calloc(g_export_max_clients + 1, sizeof(*export_clients));
  export_buckets = calloc(buckets, sizeof(*export_buckets));
  if (!export_clients || !export_buckets)
    exerr("Cannot allocate export rate limiter");
}

void http_export_deinit(void) {
  free(export_clients);
  free(export_buckets);
  export_clients = NULL;
  export_buckets = NULL;
  first_client = client_count = 0;
}

static void expire_export_clients(ot_time now) {
  /* All clients have the same interval, so deadlines follow insertion order. */
  while (client_count) {
    struct export_client *old = &export_clients[first_client + 1];
    if (old->until > now)
      break;
    if (old->previous)
      export_clients[old->previous].next = old->next;
    else
      export_buckets[old->bucket] = old->next;
    if (old->next)
      export_clients[old->next].previous = old->previous;
    first_client = (first_client + 1) % g_export_max_clients;
    --client_count;
  }
}

static unsigned export_wait(const ot_ip6 ip) {
  if (!export_clients)
    return 0;
  uint32_t hash = hash_seed;
  for (size_t i = 0; i < sizeof(ot_ip6); ++i)
    hash = (hash ^ (unsigned char)ip[i]) * UINT32_C(16777619);
  unsigned bucket = (hash ^ (hash >> 16)) & bucket_mask;
  unsigned wait = 0;
  pthread_mutex_lock(&export_lock);
  ot_time now = time_now_seconds();
  expire_export_clients(now);
  for (unsigned id = export_buckets[bucket]; id; id = export_clients[id].next) {
    if (!memcmp(export_clients[id].ip, ip, sizeof(ot_ip6))) {
      wait = (unsigned)(export_clients[id].until - now);
      break;
    }
  }
  if (!wait && client_count == g_export_max_clients)
    wait = (unsigned)(export_clients[first_client + 1].until - now);
  if (!wait) {
    unsigned id = 1 + (first_client + client_count) % g_export_max_clients;
    struct export_client *client = &export_clients[id];
    memcpy(client->ip, ip, sizeof(ot_ip6));
    client->until = now + g_export_interval;
    client->bucket = bucket;
    client->previous = 0;
    client->next = export_buckets[bucket];
    if (client->next)
      export_clients[client->next].previous = id;
    export_buckets[bucket] = id;
    ++client_count;
  }
  pthread_mutex_unlock(&export_lock);
  return wait;
}

static void api_ip(const struct http_data *client, struct ot_workstruct *ws, ot_ip6 ip) {
  memcpy(ip, client->ip, sizeof(ot_ip6));
  if (!accesslist_is_blessed(client->ip, OT_PERMISSION_MAY_PROXY))
    return;
  int chain = !strcmp(g_ip_header, "x-forwarded-for");
  size_t name_len = strlen(g_ip_header);
  int found = 0;
  const char *line = ws->request, *end = ws->request + ws->header_size;
  while (line < end) {
    const char *lf = memchr(line, '\n', (size_t)(end - line));
    if (!lf)
      break;
    if ((size_t)(lf - line) > name_len && line[name_len] == ':' && !strncasecmp(line, g_ip_header, name_len)) {
      const char *value = line + name_len + 1, *stop = lf;
      if (stop > value && stop[-1] == '\r')
        --stop;
      for (;;) {
        const char *comma = memchr(value, ',', (size_t)(stop - value));
        const char *last = comma ? comma : stop;
        while (value < last && (*value == ' ' || *value == '\t'))
          ++value;
        while (last > value && (last[-1] == ' ' || last[-1] == '\t'))
          --last;
        ot_ip6 addr;
        if (last == value || ip_parse(value, addr) != (size_t)(last - value) || (!chain && (found || comma))) {
          memcpy(ip, client->ip, sizeof(ot_ip6));
          return;
        }
        found = 1;
        if (!chain || !accesslist_is_blessed(addr, OT_PERMISSION_MAY_PROXY))
          memcpy(ip, addr, sizeof(ot_ip6));
        if (!comma)
          break;
        value = comma + 1;
      }
    }
    line = lf + 1;
  }
}

static ssize_t http_handle_fullscrape(const int64_t sock, struct ot_workstruct *ws, int format) {
  struct http_data *cookie = fdstate_cookie(sock);

  if (!cookie)
    HTTPERROR_500;
  ot_ip6 address;
  api_ip(cookie, ws, address);
  if (format == TASK_FULLSCRAPE_NDJSON && !g_export_enabled)
    HTTPERROR_404;

#ifdef WANT_RESTRICT_FULLSCRAPE
  if (!accesslist_is_blessed(address, OT_PERMISSION_MAY_FULLSCRAPE))
    HTTPERROR_403_IP;
#endif

  if (format == TASK_FULLSCRAPE_NDJSON) {
    atomic_fetch_add_explicit(ws->counters + OT_COUNTER_EXPORT, 1, memory_order_relaxed);
    unsigned retry = export_wait(address);
    if (retry) {
      ws->reply = ws->outbuf;
      ws->reply_size =
          snprintf(ws->reply, G_OUTBUF_SIZE,
                   "HTTP/1.1 429 Too Many Requests\r\nRetry-After: %u\r\nContent-Length: 0\r\n\r\n", retry);
      http_senddata(sock, ws);
      return ws->reply_size = -2;
    }
  }
#ifdef WANT_MODEST_FULLSCRAPES
  {
    ot_scrape_log this_peer, *new_peer;
    int exactmatch;
    memcpy(this_peer.ip, cookie->ip, sizeof(ot_ip6));
    this_peer.last_fullscrape = time_now_seconds();
    pthread_mutex_lock(&g_modest_fullscrape_mutex);
    new_peer = vector_find_or_insert(&g_modest_fullscrape_timeouts, &this_peer, sizeof(ot_scrape_log), sizeof(ot_ip6),
                                     &exactmatch);
    if (!new_peer) {
      pthread_mutex_unlock(&g_modest_fullscrape_mutex);
      HTTPERROR_500;
    }
    if (exactmatch && time_since_seconds(new_peer->last_fullscrape) < OT_MODEST_PEER_TIMEOUT) {
      pthread_mutex_unlock(&g_modest_fullscrape_mutex);
      HTTPERROR_402_NOTMODEST;
    }
    memcpy(new_peer, &this_peer, sizeof(ot_scrape_log));
    pthread_mutex_unlock(&g_modest_fullscrape_mutex);
  }
#endif

#if defined(WANT_COMPRESSION_GZIP) || defined(WANT_COMPRESSION_ZSTD)
  ws->request[ws->request_size - 1] = 0;
#ifdef WANT_COMPRESSION_GZIP
  if (accepts_gzip(ws)) {
    cookie->flag |= STRUCT_HTTP_FLAG_GZIP;
    format |= TASK_FLAG_GZIP;
  }
#endif
#ifdef WANT_COMPRESSION_ZSTD
  if (strstr(ws->request, "zstd")) {
    cookie->flag |= STRUCT_HTTP_FLAG_ZSTD;
    format |= TASK_FLAG_ZSTD;
  }
#endif

#if defined(WANT_COMPRESSION_ZSTD) && defined(WANT_COMPRESSION_ZSTD_ALWAYS)
  cookie->flag |= STRUCT_HTTP_FLAG_ZSTD;
  format |= TASK_FLAG_ZSTD;
#endif

#if defined(WANT_COMPRESSION_GZIP) && defined(WANT_COMPRESSION_GZIP_ALWAYS)
  cookie->flag |= STRUCT_HTTP_FLAG_GZIP;
  format |= TASK_FLAG_GZIP;
#endif
#endif

  stats_issue_event(ws, EVENT_FULLSCRAPE_REQUEST, 0, (uintptr_t)cookie->ip);

  if ((format & TASK_TASK_MASK) == TASK_FULLSCRAPE_NDJSON) {
    cookie->flag |= STRUCT_HTTP_FLAG_NDJSON;
    cookie->flag &= ~STRUCT_HTTP_FLAG_KEEPALIVE;
    ws->keep_alive = 0;
  }

  cookie->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK | STRUCT_HTTP_FLAG_CHUNKED;

  fdstate_set_expiry(sock, 0);
  http_interest_set(sock, cookie, 0);

  if (!http_adopt(sock))
    HTTPERROR_500;
  ws->handed_off = 1;
  fullscrape_deliver(sock, format);
  return ws->reply_size = -2;
}
#endif

static int compare_hash(const void *left, const void *right) { return memcmp(left, right, sizeof(ot_hash)); }

static ssize_t http_handle_scrape(const int64_t sock, struct ot_workstruct *ws, char *read_ptr) {
  static const ot_keywords keywords_scrape[] = {{"info_hash", 1}, {NULL, -3}};

  ot_hash *multiscrape_buf = (ot_hash *)ws->request;
  char *reply = ws->reply;
  int scanon = 1;
  size_t i, unique, numwant = 0;

  if (read_ptr[-1] != '?') {
    while ((*read_ptr != '?') && (*read_ptr != '\n'))
      ++read_ptr;
    if (*read_ptr == '\n')
      HTTPERROR_400_PARAM;
    ++read_ptr;
  }

  while (scanon) {
    switch (
        urlencoded_match_keyword(keywords_scrape, &read_ptr, ws->request + ws->request_size, SCAN_SEARCHPATH_PARAM)) {
    case -2:
      scanon = 0;
      break;
    default:
      HTTPERROR_400_PARAM;
    case -3:
      urlencoded_skip_value(&read_ptr);
      break;
    case 1: {

      ot_hash *slot = multiscrape_buf + numwant++;
      if (urlencoded_parse(&read_ptr, (char *)slot, (char *)(slot + 1), SCAN_SEARCHPATH_VALUE) !=
          (ssize_t)sizeof(ot_hash))
        HTTPERROR_400_PARAM;
    } break;
    }
  }

  if (!numwant)
    HTTPERROR_400_PARAM;

  if (numwant > (size_t)g_max_scrape_http)
    HTTPERROR_400_PARAM;

  qsort(multiscrape_buf, numwant, sizeof(ot_hash), compare_hash);
  for (i = unique = 1; i < numwant; ++i)
    if (memcmp(multiscrape_buf[i], multiscrape_buf[unique - 1], sizeof(ot_hash)))
      memcpy(multiscrape_buf[unique++], multiscrape_buf[i], sizeof(ot_hash));
  numwant = unique;

  return_tcp_scrape_for_torrent((const ot_hash *)multiscrape_buf, numwant, &reply, ws->outbuf + G_OUTBUF_SIZE);
  ws->reply_size = reply - ws->reply;
  stats_issue_event(ws, EVENT_SCRAPE, FLAG_TCP, ws->reply_size);
  return ws->reply_size;
}

#ifdef WANT_LOG_NUMWANT
unsigned long long numwants[201];
#endif

#if defined(WANT_KEEPALIVE) || defined(WANT_IP_FROM_PROXY)
static char *http_header(char *data, size_t byte_count, const char *header) {
  size_t i;
  long sl = strlen(header);
  for (i = 0; i + sl + 2 < byte_count; ++i) {
    if (data[i] != '\n' || data[i + sl + 1] != ':')
      continue;
    if (strncasecmp(data + i + 1, header, sl))
      continue;
    data += i + sl + 2;
    while (*data == ' ' || *data == '\t')
      ++data;
    return data;
  }
  return 0;
}
#endif

static ot_keywords keywords_announce[] = {{"port", 1},    {"left", 2},     {"event", 3},     {"numwant", 4},
                                          {"compact", 5}, {"compact6", 5}, {"info_hash", 6},
#ifdef WANT_IP_FROM_QUERY_STRING
                                          {"ip", 7},
#endif
                                          {"peer_id", 8}, {NULL, -3}};
static ot_keywords keywords_announce_event[] = {{"completed", 1}, {"stopped", 2}, {NULL, -3}};

static ssize_t reply_literal(struct ot_workstruct *ws, const char *text) {
  char *reply = ws->reply;

  fmt_bytes(&reply, ws->outbuf + G_OUTBUF_SIZE, text, strlen(text));
  return reply - ws->reply;
}

static ssize_t http_handle_announce(const int64_t sock, struct ot_workstruct *ws, char *read_ptr) {
  size_t numwant;
  int64_t tmp;
  int scanon;
  unsigned short port = 0;
  char *write_ptr;
  ssize_t len;
  struct http_data *cookie = fdstate_cookie(sock);

  if (read_ptr[-1] != '?') {
    while ((*read_ptr != '?') && (*read_ptr != '\n'))
      ++read_ptr;
    if (*read_ptr == '\n')
      HTTPERROR_400_PARAM;
    ++read_ptr;
  }

  ot_ip6 address;
  api_ip(cookie, ws, address);
  OT_SETIP(ws->peer, address);

  ws->peer_id = NULL;
  ws->hash = NULL;

  OT_SETPORT(ws->peer, &port);
  OT_PEERFLAG(ws->peer) = 0;
  numwant = g_default_numwant;
  scanon = 1;

  while (scanon) {
    switch (
        urlencoded_match_keyword(keywords_announce, &read_ptr, ws->request + ws->request_size, SCAN_SEARCHPATH_PARAM)) {
    case -2:
      scanon = 0;
      break;
    case -1:
      HTTPERROR_400_PARAM;
    case -3:
      urlencoded_skip_value(&read_ptr);
      break;
    case 1:
      len = urlencoded_parse(&read_ptr, write_ptr = read_ptr, ws->request + ws->request_size, SCAN_SEARCHPATH_VALUE);
      if ((len <= 0) || scan_int(write_ptr, len, &tmp) || (tmp > 0xffff))
        HTTPERROR_400_PARAM;
      port = htons((uint16_t)tmp);
      OT_SETPORT(&ws->peer, &port);
      break;
    case 2:
      if ((len = urlencoded_parse(&read_ptr, write_ptr = read_ptr, ws->request + ws->request_size,
                                  SCAN_SEARCHPATH_VALUE)) <= 0)
        HTTPERROR_400_PARAM;
      if (scan_int(write_ptr, len, &tmp))
        tmp = 0;
      if (!tmp)
        OT_PEERFLAG(&ws->peer) |= PEER_FLAG_SEEDING;
      break;
    case 3:
      switch (urlencoded_match_keyword(keywords_announce_event, &read_ptr, ws->request + ws->request_size,
                                       SCAN_SEARCHPATH_VALUE)) {
      case -1:
        HTTPERROR_400_PARAM;
      case 1:
        OT_PEERFLAG(&ws->peer) |= PEER_FLAG_COMPLETED;
        break;
      case 2:
        OT_PEERFLAG(&ws->peer) |= PEER_FLAG_STOPPED;
        break;
      default:
        break;
      }
      break;
    case 4:
      len = urlencoded_parse(&read_ptr, write_ptr = read_ptr, ws->request + ws->request_size, SCAN_SEARCHPATH_VALUE);
      if ((len <= 0) || scan_int(write_ptr, len, &tmp))
        HTTPERROR_400_PARAM;
      if (tmp < 0)
        tmp = g_default_numwant;
      if (tmp > g_max_http)
        tmp = g_max_http;
      numwant = (size_t)tmp;
      break;
    case 5:
      len = urlencoded_parse(&read_ptr, write_ptr = read_ptr, ws->request + ws->request_size, SCAN_SEARCHPATH_VALUE);
      if ((len <= 0) || scan_int(write_ptr, len, &tmp))
        HTTPERROR_400_PARAM;
      if (!tmp)
        HTTPERROR_400_COMPACT;
      break;
    case 6:
      if (ws->hash)
        HTTPERROR_400_DOUBLEHASH;

      if (urlencoded_parse(&read_ptr, write_ptr = read_ptr, ws->request + ws->request_size, SCAN_SEARCHPATH_VALUE) !=
          20)
        HTTPERROR_400_PARAM;
      ws->hash = (ot_hash *)write_ptr;
      break;
#ifdef WANT_IP_FROM_QUERY_STRING
    case 7: {
      char *tmp_buf1 = ws->reply, *tmp_buf2 = ws->reply + 16;
      len = urlencoded_parse(&read_ptr, tmp_buf2, ws->outbuf + G_OUTBUF_SIZE, SCAN_SEARCHPATH_VALUE);
      if (len <= 0)
        HTTPERROR_400_PARAM;
      tmp_buf2[len] = 0;
      if (ip_parse(tmp_buf2, tmp_buf1) != (size_t)len)
        HTTPERROR_400_PARAM;
      OT_SETIP(&ws->peer, tmp_buf1);
    } break;
#endif
    case 8:

      if (urlencoded_parse(&read_ptr, write_ptr = read_ptr, ws->request + ws->request_size, SCAN_SEARCHPATH_VALUE) !=
          20)
        HTTPERROR_400_PARAM;
      ws->peer_id = write_ptr;
      break;
    }
  }

#ifdef WANT_LOG_NUMWANT
  numwants[numwant]++;
#endif

  if (!ws->hash)
    return ws->reply_size = reply_literal(ws, "d14:failure reason80:Your client forgot to send your torrent's "
                                              "info_hash. Please upgrade your client.e");

  if (OT_PEERFLAG(&ws->peer) & PEER_FLAG_STOPPED)
    ws->reply_size = remove_peer_from_torrent(FLAG_TCP, ws);
  else
    ws->reply_size = add_peer_to_torrent_and_return_peers(FLAG_TCP, ws, numwant);

  stats_issue_event(ws, EVENT_ANNOUNCE, FLAG_TCP, ws->reply_size);
  return ws->reply_size;
}

ssize_t http_handle_request(const int64_t sock, struct ot_workstruct *ws) {
  ssize_t reply_off, len;
  char *read_ptr = ws->request, *write_ptr;

  ws->reply = ws->outbuf + SUCCESS_HTTP_HEADER_LENGTH;

  ws->keep_alive = 0;
  ws->handed_off = 0;
#ifdef WANT_KEEPALIVE
  if (g_keepalive && (write_ptr = http_header(ws->request, ws->header_size, "connection")) &&
      (*write_ptr == 'K' || *write_ptr == 'k'))
    ws->keep_alive = 1;
#endif
  {
    struct http_data *connection = fdstate_cookie(sock);
    if (connection) {
      if (ws->keep_alive)
        connection->flag |= STRUCT_HTTP_FLAG_KEEPALIVE;
      else
        connection->flag &= ~STRUCT_HTTP_FLAG_KEEPALIVE;
    }
  }

  if (ws->request_size < 5 || memcmp(read_ptr, "GET /", 5))
    HTTPERROR_400;

  if (diag_slots) {
    struct http_data *c = fdstate_cookie(sock);
    ot_ip6 addr;
    if (c) {
      api_ip(c, ws, addr);
      if (accesslist_is_blessed(addr, OT_PERMISSION_RECORD))
        diag_record(addr, ws->request, ws->header_size);
    }
  }

  for (read_ptr += 4; *read_ptr == '/'; ++read_ptr)
    ;

  len = urlencoded_parse(&read_ptr, write_ptr = read_ptr, ws->request + ws->request_size, SCAN_PATH);

  if (g_redirecturl && (len == -2))
    HTTPERROR_302;
  if (len <= 0)
    HTTPERROR_404;

  int route = http_route_lookup(write_ptr, (size_t)len);
  struct catalog_query query = {0};
  int diag = route == R_LOG || route == R_BUSY;
  if ((route == R_LOG && !diag_slots) || (route == R_BUSY && !busy_slots))
    HTTPERROR_404;
  int catalog = diag || route == R_PAGE || route == R_TOP || route == R_NETWORKS;
  if (catalog)
    query.kind = route == R_LOG    ? CATALOG_LOG
                 : route == R_BUSY ? CATALOG_BUSY
                 : route == R_PAGE ? CATALOG_PAGE
                 : route == R_TOP  ? CATALOG_TOP
                                   : CATALOG_NETWORKS;
  if (catalog || route == R_HEALTH || route == R_METRICS || route == R_STATS) {
    char body[256];
    const char *type = "application/json";
    if (route == R_HEALTH) {
      strcpy(body, "{\"status\":\"ok\",\"version\":\"" TRACKER_VERSION "\"}\n");
    } else {
      struct http_data *cookie = fdstate_cookie(sock);
      if (!cookie)
        HTTPERROR_500;
      ot_ip6 address;
      api_ip(cookie, ws, address);
      if (!accesslist_is_blessed(address, diag ? OT_PERMISSION_DIAG : OT_PERMISSION_MAY_STAT))
        HTTPERROR_403_IP;
      if (catalog && read_ptr[-1] == '?') {
        const char *space = memchr(read_ptr, ' ', ws->request + ws->header_size - read_ptr);
        if (!space || catalog_parse(&query, read_ptr, (size_t)(space - read_ptr)))
          HTTPERROR_400_PARAM;
      } else if (catalog)
        catalog_parse(&query, "", 0);
      int json = route != R_METRICS;
      cookie->flag |= STRUCT_HTTP_FLAG_WAITINGFORTASK;
      if (json)
        cookie->flag |= STRUCT_HTTP_FLAG_JSON;
      cookie->flag &= ~STRUCT_HTTP_FLAG_KEEPALIVE;
      ws->keep_alive = 0;
      fdstate_set_expiry(sock, 0);
      http_interest_set(sock, cookie, 0);
      if (!http_adopt(sock))
        HTTPERROR_500;
      ws->handed_off = 1;
      if (workqueue_pushquery(sock,
                              catalog ? TASK_STATS_CATALOG
                              : json  ? TASK_STATS_JSON
                                      : TASK_STATS_METRICS,
                              &query)) {
        ws->handed_off = 0;
        HTTPERROR_500;
      }
      return 0;
    }
    ws->reply = ws->outbuf;
    ws->reply_size =
        snprintf(ws->reply, G_OUTBUF_SIZE, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n%s", type,
                 strlen(body), body);
    http_senddata(sock, ws);
    return ws->reply_size;
  }
#ifdef WANT_FULLSCRAPE
  if (route == R_EXPORT)
    http_handle_fullscrape(sock, ws, TASK_FULLSCRAPE_NDJSON);
  else
#endif
      if (route == R_ANNOUNCE)
    http_handle_announce(sock, ws, read_ptr);
#ifdef WANT_FULLSCRAPE
  else if (route == R_SCRAPE && *read_ptr == ' ')
    http_handle_fullscrape(sock, ws, 0);
#endif

  else if (route == R_SCRAPE)
    http_handle_scrape(sock, ws, read_ptr);

  else if (len == g_stats_path_len && !memcmp(write_ptr, g_stats_path, len))
    http_handle_stats(sock, ws, read_ptr);
  else
    HTTPERROR_404;

  if (ws->reply_size == -2)
    return 0;

  if (ws->reply_size <= 0)
    HTTPERROR_500;

  reply_off = SUCCESS_HTTP_SIZE_OFF - snprintf(ws->outbuf, 0, "%zd", ws->reply_size);
  ws->reply = ws->outbuf + reply_off;

  ws->reply_size +=
      1 + snprintf(ws->reply, (size_t)(SUCCESS_HTTP_HEADER_LENGTH - reply_off),
                   "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zd\r\n\r", ws->reply_size);

  ws->outbuf[SUCCESS_HTTP_HEADER_LENGTH - 1] = '\n';

  http_senddata(sock, ws);
  return ws->reply_size;
}

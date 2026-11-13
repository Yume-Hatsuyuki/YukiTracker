/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <ctype.h>
#include <yaml.h>
#include "diagnostics.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ot_accesslist.h"
#include "ot_event.h"
#include "ot_config.h"
#include "ot_http.h"
#include "ot_ip.h"
#include "ot_livesync.h"
#include "ot_scan.h"
#include "ot_stats.h"
#include "trackerlogic.h"

const char *g_redirecturl;
const char *g_serverdir;
const char *g_serveruser;
const char *g_statefile, *g_snapshot;
unsigned g_export_max_clients = 4096, g_save_period, g_export_interval, g_export_enabled = 1, g_gzip = 1;
const char *g_ip_header = "x-forwarded-for";

static struct {
  const char *key, *path;
  size_t length;
} routes[R_COUNT] = {{"paths.announce", "announce", 0},
                     {"paths.scrape", "scrape", 0},
                     {"paths.health", "healthz", 0},
                     {"paths.metrics", "metrics", 0},
                     {"paths.stats", "api/v1/stats", 0},
                     {"paths.torrents", "api/v1/stats/torrents", 0},
                     {"paths.top", "api/v1/stats/top", 0},
                     {"paths.networks", "api/v1/stats/networks", 0},
                     {"paths.export", "api/v1/export/torrents", 0},
                     {"paths.requests", "api/v1/diagnostics/requests", 0},
                     {"paths.busy", "api/v1/diagnostics/busy-networks", 0}};
int http_route_lookup(const char *path, size_t length) {
  for (int i = 0; i < R_COUNT; ++i)
    if (routes[i].length == length && !memcmp(path, routes[i].path, length))
      return i;
  return -1;
}

#define OT_LISTEN_INHERIT (-1)

static ot_listen *g_listen;
static size_t g_listen_count;
static int g_listen_shared;
static int g_listen_workers_udp = 1;
static int g_listen_workers_tcp = 0;

static void panic(const char *routine) __attribute__((noreturn));
static void panic(const char *routine) {
  fprintf(stderr, "%s: %s\n", routine, strerror(errno));
  exit(111);
}

static void listen_append(const ot_ip6 ip, uint16_t port, PROTO_FLAG proto, int shared, int workers) {
  ot_listen *grown = realloc(g_listen, (g_listen_count + 1) * sizeof(ot_listen));
  ot_listen *entry;

  if (!grown)
    panic("listen_append");
  g_listen = grown;

  entry = g_listen + g_listen_count++;
  memcpy(entry->ip, ip, sizeof(ot_ip6));
  entry->port = port;
  entry->proto = proto;
  entry->shared = shared;
  entry->workers = workers;
  entry->sock = -1;
}

typedef enum { LISTEN_OPTION_UNKNOWN, LISTEN_OPTION_SHARED, LISTEN_OPTION_WORKERS } listen_option_kind;

typedef struct {
  const char *name;
  size_t len;
  listen_option_kind kind;
  int takes_value;
} listen_option_key;

#define LISTEN_OPTION_KEY(s, k, v) {s, sizeof(s) - 1, k, v}

static const listen_option_key listen_option_keys[] = {
    LISTEN_OPTION_KEY("shared", LISTEN_OPTION_SHARED, 0),
    LISTEN_OPTION_KEY("workers", LISTEN_OPTION_WORKERS, 1),
};
static const size_t listen_option_count = sizeof(listen_option_keys) / sizeof(listen_option_keys[0]);

static listen_option_kind parse_listen_option(char **p) {
  size_t i;

  for (i = 0; i < listen_option_count; ++i) {
    const listen_option_key *key = &listen_option_keys[i];
    char delimiter;

    if (strncmp(*p, key->name, key->len))
      continue;

    delimiter = (*p)[key->len];
    if (key->takes_value ? delimiter != '=' : (delimiter && !isspace((unsigned char)delimiter)))
      continue;

    *p += key->len + (key->takes_value ? 1 : 0);
    return key->kind;
  }
  return LISTEN_OPTION_UNKNOWN;
}

static int listen_scan_options(char *p, int *shared, int *workers) {
  uint64_t value;

  for (;;) {
    while (isspace((unsigned char)*p))
      ++p;
    if (!*p)
      return 1;

    switch (parse_listen_option(&p)) {
    case LISTEN_OPTION_SHARED:
      *shared = 1;
      break;
    case LISTEN_OPTION_WORKERS: {
      size_t off = scan_uint(p, &value, OT_MAX_THREADS);

      if (!off)
        return 0;
      *workers = (int)value;
      p += off;
      break;
    }
    default:
      return 0;
    }
  }
}

static const char *set_config_option(const char **option, char *value) {
  while (isspace((unsigned char)*value))
    ++value;
  free((char *)*option);
  return *option = strdup(value);
}

static int scan_ip6_port(const char *src, ot_ip6 ip, uint16_t *port) {
  const char *s = src;
  uint64_t value;
  int off, bracket = 0;
  while (isspace((unsigned char)*s))
    ++s;
  if (*s == '[')
    ++s, ++bracket;
  if (!(off = ip_parse(s, ip)))
    return 0;
  s += off;
  if (bracket && *s == ']')
    ++s;
  if (*s == 0 || isspace((unsigned char)*s))
    return s - src;
  if (!ip_is_v4mapped(ip)) {
    if (*s != ':' && *s != '.')
      return 0;
    if (!bracket && *(s) == ':')
      return 0;
    s++;
  } else {
    if (*(s++) != ':')
      return 0;
  }
  if (!(off = scan_uint(s, &value, 65535)))
    return 0;
  *port = (uint16_t)value;
  return off + s - src;
}

static int scan_ip6_net(const char *src, ot_net *net) {
  const char *s = src;
  uint64_t value;
  int off;
  while (isspace((unsigned char)*s))
    ++s;
  if (!(off = ip_parse(s, net->address)))
    return 0;
  s += off;
  if (*s != '/')
    net->bits = 128;
  else {
    s++;
    if (!(off = scan_uint(s, &value, 128)))
      return 0;
    net->bits = (int)value;
    if (ip_is_v4mapped(net->address))
      net->bits += 96;
    if (net->bits > 128)
      return 0;
    s += off;
  }
  return s - src;
}

typedef enum {
  CONFIG_UNKNOWN,
  CONFIG_READ_TIMEOUT,
  CONFIG_WRITE_TIMEOUT,
  CONFIG_EXPORT_ENTRIES,
  CONFIG_RATIO,
  DIAG_ALLOW,
  DIAG_RECORD,
  DLOG,
  DBUSY,
  DGAP,
  DDECAY,
  DBITS,
  CONFIG_EXPORT_INTERVAL,
  CONFIG_EXPORT_ENABLED,
  CONFIG_GZIP,
  CONFIG_IP_HEADER,
  CONFIG_SNAPSHOT,
  CONFIG_SAVE_PERIOD,
  CONFIG_SCRAPE_HTTP,
  CONFIG_SCRAPE_UDP,
  CONFIG_KEY_MINUTES,
  CONFIG_PEER_AGE,
  CONFIG_TORRENT_AGE,
  CONFIG_INTERVAL,
  CONFIG_JITTER,
  CONFIG_DEFAULT,
  CONFIG_HTTP_MAX,
  CONFIG_UDP4_MAX,
  CONFIG_UDP6_MAX,
  CONFIG_KEEPALIVE,
  CONFIG_TRACKER_ROOTDIR,
  CONFIG_TRACKER_USER,
  CONFIG_TRACKER_EMPTY_TIMEOUT,
  CONFIG_LISTEN_TCP_UDP,
  CONFIG_LISTEN_TCP,
  CONFIG_LISTEN_UDP,
  CONFIG_LISTEN_UDP_WORKERS,
  CONFIG_LISTEN_TCP_WORKERS,
  CONFIG_LISTEN_SHARED,
  CONFIG_ACCESS_WHITELIST,
  CONFIG_ACCESS_BLACKLIST,
  CONFIG_ACCESS_FIFO_ADD,
  CONFIG_ACCESS_FIFO_DELETE,
  CONFIG_ACCESS_STATS,
  CONFIG_ACCESS_STATS_PATH,
  CONFIG_ACCESS_PROXY,
  CONFIG_ACCESS_FULLSCRAPE,
  CONFIG_TRACKER_REDIRECT_URL,
  CONFIG_LIVESYNC_CLUSTER_NODE_IP,
  CONFIG_LIVESYNC_CLUSTER_LISTEN,
  CONFIG_LIVESYNC_CLUSTER_GROUP,
} config_kind;

typedef struct {
  const char *name;
  size_t len;
  config_kind kind;
} config_key;

#define CONFIG_KEY(s, k) {s, sizeof(s) - 1, k}

static const config_key config_keys[] = {
    CONFIG_KEY("tracker.peer_timeout", CONFIG_PEER_AGE),
    CONFIG_KEY("tracker.torrent_timeout", CONFIG_TORRENT_AGE),
    CONFIG_KEY("scrape.http", CONFIG_SCRAPE_HTTP),
    CONFIG_KEY("scrape.udp", CONFIG_SCRAPE_UDP),
    CONFIG_KEY("tracker.key_minutes", CONFIG_KEY_MINUTES),
    CONFIG_KEY("http.read_timeout", CONFIG_READ_TIMEOUT),
    CONFIG_KEY("http.write_timeout", CONFIG_WRITE_TIMEOUT),
    CONFIG_KEY("export.max_clients", CONFIG_EXPORT_ENTRIES),
    CONFIG_KEY("export.min_interval", CONFIG_EXPORT_INTERVAL),
    CONFIG_KEY("export.enabled", CONFIG_EXPORT_ENABLED),
    CONFIG_KEY("compression.gzip", CONFIG_GZIP),
    CONFIG_KEY("http.client_ip_header", CONFIG_IP_HEADER),
    CONFIG_KEY("access.diagnostics", DIAG_ALLOW),
    CONFIG_KEY("access.record", DIAG_RECORD),
    CONFIG_KEY("diagnostics.log_entries", DLOG),
    CONFIG_KEY("diagnostics.busy_entries", DBUSY),
    CONFIG_KEY("diagnostics.busy_gap", DGAP),
    CONFIG_KEY("diagnostics.decay_seconds", DDECAY),
    CONFIG_KEY("diagnostics.prefix_bits", DBITS),
    CONFIG_KEY("state.file", CONFIG_SNAPSHOT),
    CONFIG_KEY("state.save_interval", CONFIG_SAVE_PERIOD),
    CONFIG_KEY("tracker.min_interval_ratio", CONFIG_RATIO),
    CONFIG_KEY("tracker.interval", CONFIG_INTERVAL),
    CONFIG_KEY("tracker.jitter", CONFIG_JITTER),
    CONFIG_KEY("numwant.default", CONFIG_DEFAULT),
    CONFIG_KEY("numwant.http", CONFIG_HTTP_MAX),
    CONFIG_KEY("numwant.udp4", CONFIG_UDP4_MAX),
    CONFIG_KEY("numwant.udp6", CONFIG_UDP6_MAX),
    CONFIG_KEY("http.keepalive", CONFIG_KEEPALIVE),
    CONFIG_KEY("tracker.rootdir", CONFIG_TRACKER_ROOTDIR),
    CONFIG_KEY("tracker.user", CONFIG_TRACKER_USER),
    CONFIG_KEY("tracker.empty_torrent_timeout", CONFIG_TRACKER_EMPTY_TIMEOUT),
    CONFIG_KEY("listen.tcp_udp", CONFIG_LISTEN_TCP_UDP),
    CONFIG_KEY("listen.tcp", CONFIG_LISTEN_TCP),
    CONFIG_KEY("listen.udp", CONFIG_LISTEN_UDP),
    CONFIG_KEY("listen.udp.workers", CONFIG_LISTEN_UDP_WORKERS),
    CONFIG_KEY("listen.tcp.workers", CONFIG_LISTEN_TCP_WORKERS),
    CONFIG_KEY("listen.shared", CONFIG_LISTEN_SHARED),
#ifdef WANT_ACCESSLIST_WHITE
    CONFIG_KEY("access.whitelist", CONFIG_ACCESS_WHITELIST),
#elif defined(WANT_ACCESSLIST_BLACK)
    CONFIG_KEY("access.whitelist", CONFIG_ACCESS_WHITELIST),
    CONFIG_KEY("access.blacklist", CONFIG_ACCESS_BLACKLIST),
#endif
#ifdef WANT_DYNAMIC_ACCESSLIST
    CONFIG_KEY("access.fifo_add", CONFIG_ACCESS_FIFO_ADD),
    CONFIG_KEY("access.fifo_delete", CONFIG_ACCESS_FIFO_DELETE),
#endif
#ifdef WANT_RESTRICT_STATS
    CONFIG_KEY("access.stats", CONFIG_ACCESS_STATS),
#endif
    CONFIG_KEY("access.stats_path", CONFIG_ACCESS_STATS_PATH),
#ifdef WANT_IP_FROM_PROXY
    CONFIG_KEY("access.proxy", CONFIG_ACCESS_PROXY),
#endif
#ifdef WANT_RESTRICT_FULLSCRAPE
    CONFIG_KEY("access.fullscrape", CONFIG_ACCESS_FULLSCRAPE),
#endif
    CONFIG_KEY("tracker.redirect_url", CONFIG_TRACKER_REDIRECT_URL),
#ifdef WANT_SYNC_LIVE
    CONFIG_KEY("livesync.cluster.node_ip", CONFIG_LIVESYNC_CLUSTER_NODE_IP),
    CONFIG_KEY("livesync.cluster.listen", CONFIG_LIVESYNC_CLUSTER_LISTEN),
    CONFIG_KEY("livesync.cluster.group", CONFIG_LIVESYNC_CLUSTER_GROUP),
#endif
};
static const size_t config_entry_count = sizeof(config_keys) / sizeof(config_keys[0]);

static config_kind parse_config_key(char **p) {
  size_t i;
  for (i = 0; i < config_entry_count; ++i) {
    const config_key *key = &config_keys[i];
    if (strncmp(*p, key->name, key->len) == 0 && isspace((unsigned char)(*p)[key->len])) {
      *p += key->len + 1;

      while (isspace((unsigned char)**p))
        ++(*p);
      return key->kind;
    }
  }
  return CONFIG_UNKNOWN;
}

static int apply_line(char *inbuf) {
  ot_ip6 tmpip;
  ot_net tmpnet;
  int bound = 0;
  uint64_t value;
  uint16_t tmpport = 6969;
  config_kind kind;
  char *p = inbuf, *end;
  while (isspace((unsigned char)*p))
    ++p;
  if (!*p || *p == '#')
    return 0;
  end = p + strlen(p);
  while (end > p && isspace((unsigned char)end[-1]))
    *--end = 0;
  for (int i = 0; i < R_COUNT; ++i) {
    size_t n = strlen(routes[i].key);
    if (!strncmp(p, routes[i].key, n) && isspace((unsigned char)p[n])) {
      p += n;
      while (isspace((unsigned char)*p))
        ++p;
      if (*p++ != '/' || !*p ||
          strspn(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/") != strlen(p))
        exerr("Invalid HTTP route");
      if (routes[i].length)
        exerr("Duplicate HTTP route setting");
      routes[i].path = strdup(p);
      if (!routes[i].path)
        exerr("Out of memory");
      routes[i].length = strlen(p);
      return 0;
    }
  }

  kind = parse_config_key(&p);
  switch (kind) {
  case CONFIG_PEER_AGE:
    if (scan_uint(p, &value, 255) != strlen(p) || !value)
      goto parse_error;
    g_peer_timeout = (int)value;
    break;
  case CONFIG_TORRENT_AGE:
    if (scan_uint(p, &value, 525600) != strlen(p) || !value)
      goto parse_error;
    g_torrent_timeout = (int)value;
    break;
  case CONFIG_SCRAPE_HTTP:
    if (scan_uint(p, &value, 64) != strlen(p) || !value)
      goto parse_error;
    g_max_scrape_http = (int)value;
    break;
  case CONFIG_SCRAPE_UDP:
    if (scan_uint(p, &value, 74) != strlen(p) || !value)
      goto parse_error;
    g_max_scrape_udp = (int)value;
    break;
  case CONFIG_KEY_MINUTES:
    if (scan_uint(p, &value, 1440) != strlen(p) || !value)
      goto parse_error;
    g_key_minutes = (int)value;
    break;
  case CONFIG_IP_HEADER:
    if (!strcmp(p, "CF-Connecting-IP"))
      g_ip_header = "cf-connecting-ip";
    else if (!strcmp(p, "X-Forwarded-For"))
      g_ip_header = "x-forwarded-for";
    else
      goto parse_error;
    break;
  case CONFIG_READ_TIMEOUT:
  case CONFIG_WRITE_TIMEOUT:
    if (scan_uint(p, &value, 86400) != strlen(p) || !value)
      goto parse_error;
    if (kind == CONFIG_READ_TIMEOUT)
      g_http_read_timeout = (int)value;
    else
      g_http_write_timeout = (int)value;
    break;
  case CONFIG_EXPORT_ENTRIES:
    if (scan_uint(p, &value, 65536) != strlen(p) || !value)
      goto parse_error;
    g_export_max_clients = (unsigned)value;
    break;
  case CONFIG_EXPORT_INTERVAL:
    if (scan_uint(p, &value, 86400) != strlen(p))
      goto parse_error;
    g_export_interval = (unsigned)value;
    break;
  case CONFIG_EXPORT_ENABLED:
  case CONFIG_GZIP:
    if (scan_uint(p, &value, 1) != strlen(p))
      goto parse_error;
    if (kind == CONFIG_GZIP)
      g_gzip = (unsigned)value;
    else
      g_export_enabled = (unsigned)value;
    break;
  case DIAG_ALLOW:
  case DIAG_RECORD:
    if (scan_ip6_net(p, &tmpnet) != (int)strlen(p) ||
        accesslist_bless_net(&tmpnet, kind == DIAG_ALLOW ? OT_PERMISSION_DIAG : OT_PERMISSION_RECORD))
      goto parse_error;
    break;
  case DLOG:
    if (scan_uint(p, &value, 10000) != strlen(p))
      goto parse_error;
    diag_slots = (unsigned)value;
    break;
  case DBUSY:
    if (scan_uint(p, &value, 65536) != strlen(p))
      goto parse_error;
    busy_slots = (unsigned)value;
    break;
  case DGAP:
    if (scan_uint(p, &value, 255) != strlen(p) || value < 1)
      goto parse_error;
    busy_gap = (unsigned)value;
    break;
  case DDECAY:
    if (scan_uint(p, &value, 86400) != strlen(p) || value < 1)
      goto parse_error;
    busy_decay = (unsigned)value;
    break;
  case DBITS:
    if (scan_uint(p, &value, 32) != strlen(p) || value < 8)
      goto parse_error;
    busy_bits = (unsigned)value;
    break;
  case CONFIG_RATIO: {
    char *after;
    double ratio = strtod(p, &after);
    if (*after || !(ratio > 0 && ratio <= 1))
      goto parse_error;
    g_min_ratio = ratio;
    break;
  }
  case CONFIG_SNAPSHOT:
    set_config_option(&g_snapshot, p);
    break;
  case CONFIG_SAVE_PERIOD:
    if (scan_uint(p, &value, 604800) != strlen(p))
      goto parse_error;
    g_save_period = value;
    break;
  case CONFIG_INTERVAL:
    if (scan_uint(p, &value, 86400) != strlen(p) || !value)
      goto parse_error;
    g_announce_interval = (int)value;
    break;
  case CONFIG_JITTER:
    if (scan_uint(p, &value, 86400) != strlen(p))
      goto parse_error;
    g_announce_jitter = (int)value;
    break;
  case CONFIG_DEFAULT:
    if (scan_uint(p, &value, 200) != strlen(p))
      goto parse_error;
    g_default_numwant = (int)value;
    break;
  case CONFIG_HTTP_MAX:
    if (scan_uint(p, &value, 200) != strlen(p))
      goto parse_error;
    g_max_http = (int)value;
    break;
  case CONFIG_UDP4_MAX:
    if (scan_uint(p, &value, 200) != strlen(p))
      goto parse_error;
    g_max_udp4 = (int)value;
    break;
  case CONFIG_UDP6_MAX:
    if (scan_uint(p, &value, 66) != strlen(p))
      goto parse_error;
    g_max_udp6 = (int)value;
    break;
  case CONFIG_KEEPALIVE:
    if (scan_uint(p, &value, 1) != strlen(p))
      goto parse_error;
    g_keepalive = (int)value;
    break;
  case CONFIG_TRACKER_ROOTDIR:
    set_config_option(&g_serverdir, p);
    break;
  case CONFIG_TRACKER_USER:
    set_config_option(&g_serveruser, p);
    break;
  case CONFIG_TRACKER_EMPTY_TIMEOUT:
    if (scan_uint(p, &value, UINT_MAX) != strlen(p))
      goto parse_error;
    g_empty_torrent_timeout = (ot_time)value;
    break;
  case CONFIG_LISTEN_TCP_UDP:
  case CONFIG_LISTEN_TCP:
  case CONFIG_LISTEN_UDP: {
    int shared = OT_LISTEN_INHERIT;
    int workers = OT_LISTEN_INHERIT;
    int off = scan_ip6_port(p, tmpip, &tmpport);

    if (!off || !listen_scan_options(p + off, &shared, &workers))
      exerr("listen.tcp, listen.udp and listen.tcp_udp want an address, optionally a port and options.");
    if (kind != CONFIG_LISTEN_UDP)
      listen_append(tmpip, tmpport, FLAG_TCP, shared, workers), ++bound;
    if (kind != CONFIG_LISTEN_TCP)
      listen_append(tmpip, tmpport, FLAG_UDP, shared, workers), ++bound;
    break;
  }
  case CONFIG_LISTEN_UDP_WORKERS:
    if (scan_uint(p, &value, OT_MAX_THREADS) != strlen(p))
      goto parse_error;
    g_listen_workers_udp = (int)value;
    break;
  case CONFIG_LISTEN_TCP_WORKERS:
    if (scan_uint(p, &value, OT_MAX_THREADS) != strlen(p))
      goto parse_error;
    g_listen_workers_tcp = (int)value;
    break;
  case CONFIG_LISTEN_SHARED:
    if (scan_uint(p, &value, 1) != strlen(p))
      goto parse_error;
    g_listen_shared = (int)value;
    break;
#ifdef WANT_ACCESSLIST_WHITE
  case CONFIG_ACCESS_WHITELIST:
    set_config_option(&g_accesslist_filename, p);
    break;
#elif defined(WANT_ACCESSLIST_BLACK)
  case CONFIG_ACCESS_WHITELIST:
  case CONFIG_ACCESS_BLACKLIST:
    if (g_accesslist_filename)
      exerr("Choose one access list");
    g_whitelist = kind == CONFIG_ACCESS_WHITELIST;
    set_config_option(&g_accesslist_filename, p);
    break;
#endif
#ifdef WANT_DYNAMIC_ACCESSLIST
  case CONFIG_ACCESS_FIFO_ADD:
    set_config_option(&g_accesslist_pipe_add, p);
    break;
  case CONFIG_ACCESS_FIFO_DELETE:
    set_config_option(&g_accesslist_pipe_delete, p);
    break;
#endif
#ifdef WANT_RESTRICT_STATS
  case CONFIG_ACCESS_STATS:
    if (scan_ip6_net(p, &tmpnet) != (int)strlen(p))
      goto parse_error;
    if (accesslist_bless_net(&tmpnet, OT_PERMISSION_MAY_STAT))
      goto parse_error;
    break;
#endif
  case CONFIG_ACCESS_STATS_PATH:
    set_config_option(&g_stats_path, p);
    break;
#ifdef WANT_IP_FROM_PROXY
  case CONFIG_ACCESS_PROXY:
    if (scan_ip6_net(p, &tmpnet) != (int)strlen(p))
      goto parse_error;
    if (accesslist_bless_net(&tmpnet, OT_PERMISSION_MAY_PROXY))
      goto parse_error;
    break;
#endif
#ifdef WANT_RESTRICT_FULLSCRAPE
  case CONFIG_ACCESS_FULLSCRAPE:
    if (scan_ip6_net(p, &tmpnet) != (int)strlen(p))
      goto parse_error;
    if (accesslist_bless_net(&tmpnet, OT_PERMISSION_MAY_FULLSCRAPE))
      goto parse_error;
    break;
#endif
  case CONFIG_TRACKER_REDIRECT_URL:
    set_config_option(&g_redirecturl, p);
    break;
#ifdef WANT_SYNC_LIVE
  case CONFIG_LIVESYNC_CLUSTER_GROUP:
    if (!ip_parse(p, tmpip) || livesync_set_group(tmpip) == -1)
      exerr("livesync.cluster.group wants a multicast address, out of 224.0.0.0/4.");
    break;
  case CONFIG_LIVESYNC_CLUSTER_NODE_IP:
    if (scan_ip6_net(p, &tmpnet) != (int)strlen(p))
      goto parse_error;
    if (accesslist_bless_net(&tmpnet, OT_PERMISSION_MAY_LIVESYNC))
      goto parse_error;
    break;
  case CONFIG_LIVESYNC_CLUSTER_LISTEN:
    tmpport = LIVESYNC_PORT;
    {
      int shared = OT_LISTEN_INHERIT, dummy = OT_LISTEN_INHERIT;
      int off = scan_ip6_port(p, tmpip, &tmpport);

      if (!off || !listen_scan_options(p + off, &shared, &dummy))
        goto parse_error;
      listen_append(tmpip, tmpport, FLAG_MCA, shared, OT_LISTEN_INHERIT);
    }
    break;
#endif
  default:
    fprintf(stderr, "Unhandled line in config file: %s\n", inbuf);
    exit(1);
  parse_error:
    fprintf(stderr, "Parse error in config file: %s\n", inbuf);
    exit(1);
  }
  return bound;
}

static int apply_yaml_pair(const char *key, const yaml_node_t *value) {
  char line[512];
  if (value->type != YAML_SCALAR_NODE || value->data.scalar.length != strlen((char *)value->data.scalar.value) ||
      strpbrk((char *)value->data.scalar.value, "\r\n") ||
      snprintf(line, sizeof(line), "%s %s", key, value->data.scalar.value) >= (int)sizeof(line))
    exerr("Expected one short scalar configuration value");
  return apply_line(line);
}

static int parse_yaml(FILE *file) {
  yaml_parser_t parser;
  yaml_document_t doc;
  int bound = 0;
  if (!yaml_parser_initialize(&parser))
    exerr("Cannot initialize YAML");
  yaml_parser_set_input_file(&parser, file);
  if (!yaml_parser_load(&parser, &doc))
    exerr("Invalid YAML configuration");
  yaml_node_t *root = yaml_document_get_root_node(&doc);
  if (!root || root->type != YAML_MAPPING_NODE)
    exerr("Expected a YAML mapping");
  if (root->data.mapping.pairs.top - root->data.mapping.pairs.start > 256)
    exerr("Too many YAML keys");
  for (yaml_node_pair_t *pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; ++pair) {
    yaml_node_t *key = yaml_document_get_node(&doc, pair->key);
    yaml_node_t *value = yaml_document_get_node(&doc, pair->value);
    if (key->type != YAML_SCALAR_NODE || !key->data.scalar.length ||
        key->data.scalar.length != strspn((char *)key->data.scalar.value, "abcdefghijklmnopqrstuvwxyz_0123456789."))
      exerr("Invalid configuration key");
    const char *name = (char *)key->data.scalar.value;
    for (yaml_node_pair_t *prev = root->data.mapping.pairs.start; prev < pair; ++prev) {
      yaml_node_t *other = yaml_document_get_node(&doc, prev->key);
      if (!strcmp((char *)other->data.scalar.value, name))
        exerr("Duplicate YAML key");
    }
    if (value->type == YAML_SEQUENCE_NODE) {
      if (strncmp(name, "access.", 7) && strcmp(name, "listen.tcp") && strcmp(name, "listen.udp") &&
          strcmp(name, "listen.tcp_udp"))
        exerr("Sequence only supported for listen or access entries");
      if (value->data.sequence.items.start == value->data.sequence.items.top)
        exerr("Empty configuration sequence");
      for (yaml_node_item_t *i = value->data.sequence.items.start; i < value->data.sequence.items.top; ++i)
        bound += apply_yaml_pair(name, yaml_document_get_node(&doc, *i));
    } else
      bound += apply_yaml_pair(name, value);
  }
  yaml_document_delete(&doc);
  if (!yaml_parser_load(&parser, &doc) || yaml_document_get_root_node(&doc))
    exerr("Expected a single YAML document");
  yaml_document_delete(&doc);
  yaml_parser_delete(&parser);
  if (!bound)
    exerr("YAML configuration requires an explicit listener");
  return bound;
}

static int parse_configfile(char *name) {
  FILE *file = fopen(name, "r");
  const char *ext = strrchr(name, '.');
  int bound = 0;
  if (!file) {
    perror(name);
    exit(1);
  }
  if (ext && (!strcmp(ext, ".yaml") || !strcmp(ext, ".yml"))) {
    bound = parse_yaml(file);
  } else {
    char line[512];
    while (fgets(line, sizeof(line), file)) {
      if (!strchr(line, '\n') && !feof(file))
        exerr("Configuration line too long");
      bound += apply_line(line);
    }
    if (ferror(file))
      exerr("Cannot read configuration");
  }
  fclose(file);
  return bound;
}

static void usage(char *name) {
  fprintf(stderr,
          "Usage: %s [-i ip] [-p port] [-P port] [-r redirect] [-d dir] [-u user] [-A ip[/bits]] [-f config] [-s "
          "livesyncport]"
#ifdef WANT_ACCESSLIST_BLACK
          " [-b blacklistfile]"
#elif defined(WANT_ACCESSLIST_WHITE)
          " [-w whitelistfile]"
#endif
          "\n",
          name);
}

#define HELPLINE(opt, desc) fprintf(stderr, "\t%-10s%s\n", opt, desc)
static void help(char *name) {
  usage(name);

  HELPLINE("-C", "validate configuration and exit");
  HELPLINE("-f config", "include and execute the config file");
  HELPLINE("-i ip", "specify ip to bind to with next -[pP] (default: any, overrides preceeding ones)");
  HELPLINE("-p port", "do bind to tcp port (default: 6969, you may specify more than one)");
  HELPLINE("-P port", "do bind to udp port (default: 6969, you may specify more than one)");
  HELPLINE("-r redirecturl", "specify url where / should be redirected to (default none)");
  HELPLINE("-d dir", "specify directory to try to chroot to (default: \".\")");
  HELPLINE("-u user", "specify user under whose privileges YukiTracker should run (default: \"nobody\")");
  HELPLINE("-A ip[/bits]", "bless an ip address or net as admin address (e.g. to allow syncs from this address)");
  HELPLINE("-v", "report version, event mechanism and the feature flags YukiTracker was built with");
#ifdef WANT_ACCESSLIST_BLACK
  HELPLINE("-b file", "specify blacklist file.");
#elif defined(WANT_ACCESSLIST_WHITE)
  HELPLINE("-w file", "specify whitelist file.");
#endif

  fprintf(stderr,
          "\nExample:   ./yukitracker -i 127.0.0.1 -p 6969 -P 6969 -f ./yukitracker.yaml -i 10.1.1.23 -p 2710 -p 80\n");
  fprintf(stderr, "           Here -i 127.0.0.1 selects the ip address for the next -p 6969 and -P 6969.\n");
  fprintf(stderr, "           If no port is bound from config file or command line, the last address given\n");
  fprintf(stderr, "           is used on port 6969, and every interface if none was given.\n");
}
#undef HELPLINE

static void listen_resolve_defaults(void) {
  size_t i;

  for (i = 0; i < g_listen_count; ++i) {
    ot_listen *entry = g_listen + i;

    if (entry->shared == OT_LISTEN_INHERIT)
      entry->shared = g_listen_shared;
    if (entry->workers == OT_LISTEN_INHERIT)
      entry->workers = entry->proto == FLAG_TCP ? g_listen_workers_tcp : g_listen_workers_udp;

    if (entry->proto == FLAG_TCP && entry->workers > 1 && !event_can_share()) {
      fprintf(stderr, "Warning: Multiple workers impossible on this platform with event mechanism %s chosen.\n",
              event_mechanism());
      entry->workers = 1;
    }
  }
}

ot_listen *config_listen_entries(size_t *count) {
  *count = g_listen_count;
  return g_listen;
}

void config_parse(int argc, char **argv) {
  ot_ip6 serverip;
  ot_net tmpnet;
  int bound = 0, scanon = 1, check = 0;
  uint64_t value;

  memset(serverip, 0, sizeof(ot_ip6));
#ifdef WANT_V4_ONLY
  serverip[10] = serverip[11] = -1;
#endif

  while (scanon) {
    switch (getopt(argc, argv,
                   ":Ci:p:A:P:d:u:r:s:f:l:v"
#ifdef WANT_ACCESSLIST_BLACK
                   "b:"
#elif defined(WANT_ACCESSLIST_WHITE)
                   "w:"
#endif
                   "h")) {
    case -1:
      scanon = 0;
      break;
    case 'C':
      check = 1;
      break;
    case 'i':
      if (!ip_parse(optarg, serverip)) {
        usage(argv[0]);
        exit(1);
      }
      break;
#ifdef WANT_ACCESSLIST_BLACK
    case 'b':
      set_config_option(&g_accesslist_filename, optarg);
      break;
#elif defined(WANT_ACCESSLIST_WHITE)
    case 'w':
      set_config_option(&g_accesslist_filename, optarg);
      break;
#endif
    case 'p':
      if (!scan_uint(optarg, &value, 65535)) {
        usage(argv[0]);
        exit(1);
      }
      listen_append(serverip, (uint16_t)value, FLAG_TCP, OT_LISTEN_INHERIT, OT_LISTEN_INHERIT);
      bound++;
      break;
    case 'P':
      if (!scan_uint(optarg, &value, 65535)) {
        usage(argv[0]);
        exit(1);
      }
      listen_append(serverip, (uint16_t)value, FLAG_UDP, OT_LISTEN_INHERIT, OT_LISTEN_INHERIT);
      bound++;
      break;
#ifdef WANT_SYNC_LIVE
    case 's':
      if (!scan_uint(optarg, &value, 65535)) {
        usage(argv[0]);
        exit(1);
      }
      listen_append(serverip, (uint16_t)value, FLAG_MCA, OT_LISTEN_INHERIT, OT_LISTEN_INHERIT);
      break;
#endif
    case 'd':
      set_config_option(&g_serverdir, optarg);
      break;
    case 'u':
      set_config_option(&g_serveruser, optarg);
      break;
    case 'r':
      set_config_option(&g_redirecturl, optarg);
      break;
    case 'l':
      g_statefile = optarg;
      break;
    case 'A':
      if (!scan_ip6_net(optarg, &tmpnet)) {
        usage(argv[0]);
        exit(1);
      }
      accesslist_bless_net(&tmpnet, 0xffff);
      break;
    case 'f':
      bound += parse_configfile(optarg);
      break;
    case 'h':
      help(argv[0]);
      exit(0);
    case 'v': {
      char buffer[8192];
      char *cursor = buffer;

      stats_return_tracker_version(&cursor, buffer + sizeof(buffer) - 1);
      stats_return_tracker_features(&cursor, buffer + sizeof(buffer) - 1);
      *cursor = 0;
      fputs(buffer, stderr);
      exit(0);
    }
    default:
    case '?':
      usage(argv[0]);
      exit(1);
    }
  }

  if (optind != argc)
    exerr("Unexpected command-line argument");
  if (g_peer_timeout > g_torrent_timeout || g_announce_jitter > g_announce_interval || g_default_numwant > g_max_http)
    exerr("Invalid jitter or default numwant");
  if (!bound) {
    listen_append(serverip, 6969, FLAG_TCP, OT_LISTEN_INHERIT, OT_LISTEN_INHERIT);
    listen_append(serverip, 6969, FLAG_UDP, OT_LISTEN_INHERIT, OT_LISTEN_INHERIT);
  }

  for (int i = 0; i < R_COUNT; ++i) {
    routes[i].length = strlen(routes[i].path);
    if (!strcmp(routes[i].path, g_stats_path ? g_stats_path : "stats"))
      exerr("Duplicate statistics path");
    for (int j = 0; j < i; ++j)
      if (!strcmp(routes[i].path, routes[j].path))
        exerr("Duplicate HTTP route");
  }
  if (g_save_period && !g_snapshot)
    exerr("state.save_interval requires state.file");
  listen_resolve_defaults();
  if (check)
    exit(0);
}

/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_CONFIG_H__
#define OT_CONFIG_H__

#include <stdint.h>

#include "trackerlogic.h"

typedef struct {
  ot_ip6 ip;
  uint16_t port;
  PROTO_FLAG proto;
  int shared;
  int workers;
  int64_t sock;
} ot_listen;

enum http_route {
  R_ANNOUNCE,
  R_SCRAPE,
  R_HEALTH,
  R_METRICS,
  R_STATS,
  R_PAGE,
  R_TOP,
  R_NETWORKS,
  R_EXPORT,
  R_LOG,
  R_BUSY,
  R_COUNT
};
int http_route_lookup(const char *path, size_t length);
extern const char *g_redirecturl;
extern const char *g_serverdir;
extern const char *g_serveruser;
extern const char *g_statefile, *g_snapshot;
extern unsigned g_export_max_clients, g_save_period, g_export_interval, g_export_enabled, g_gzip;
extern const char *g_ip_header;

void config_parse(int argc, char **argv);

ot_listen *config_listen_entries(size_t *count);

#endif

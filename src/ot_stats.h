/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_STATS_H__
#define OT_STATS_H__

#include "trackerlogic.h"

typedef enum {
  EVENT_ACCEPT,
  EVENT_READ,
  EVENT_CONNECT,
  EVENT_ANNOUNCE,
  EVENT_COMPLETED,
  EVENT_RENEW,
  EVENT_SYNC,
  EVENT_SCRAPE,
  EVENT_FULLSCRAPE_REQUEST,
  EVENT_FULLSCRAPE_REQUEST_GZIP,
  EVENT_FULLSCRAPE_REQUEST_ZSTD,
  EVENT_FULLSCRAPE,
  EVENT_FAILED,
  EVENT_BUCKET_LOCKED,
  EVENT_WOODPECKER,
  EVENT_CONNID_MISSMATCH
} ot_status_event;

void stats_counters_register(struct ot_workstruct *ws);
void stats_counters_retire(struct ot_workstruct *ws);

void stats_issue_event(struct ot_workstruct *ws, ot_status_event event, PROTO_FLAG proto, uintptr_t event_data);
void stats_deliver(int64_t sock, int tasktype);
void stats_cleanup(void);
void return_stats_for_tracker(char **reply, const char *reply_end, int mode, int format);
void stats_return_tracker_version(char **reply, const char *reply_end);
void stats_return_tracker_features(char **reply, const char *reply_end);
void stats_init(void);
void stats_deinit(void);

#endif

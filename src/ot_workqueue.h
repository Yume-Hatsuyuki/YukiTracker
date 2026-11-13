/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_WORKQUEUE_H__
#define OT_WORKQUEUE_H__

#include <stdint.h>
#include "torrent_catalog.h"
#include <sys/uio.h>

#include "trackerlogic.h"

typedef enum {
  TASK_STATS_CONNS = 0x0001,
  TASK_STATS_TCP = 0x0002,
  TASK_STATS_UDP = 0x0003,
  TASK_STATS_SCRAPE = 0x0004,
  TASK_STATS_FULLSCRAPE = 0x0005,
  TASK_STATS_TPB = 0x0006,
  TASK_STATS_HTTPERRORS = 0x0007,
  TASK_STATS_RENEW = 0x000a,
  TASK_STATS_SYNCS = 0x000b,
  TASK_STATS_COMPLETED = 0x000c,
  TASK_STATS_NUMWANTS = 0x000d,

  TASK_STATS = 0x0100,
  TASK_STATS_TORRENTS = 0x0101,
  TASK_STATS_PEERS = 0x0102,
  TASK_STATS_TOP10 = 0x0104,
  TASK_STATS_TOP100 = 0x0105,
  TASK_STATS_EVERYTHING = 0x0106,
  TASK_STATS_WOODPECKERS = 0x0108,
  TASK_STATS_CATALOG = 0x010b,
  TASK_STATS_JSON = 0x0109,
  TASK_STATS_METRICS = 0x010a,

  TASK_FULLSCRAPE = 0x0200,
  TASK_FULLSCRAPE_TPB_BINARY = 0x0201,
  TASK_FULLSCRAPE_TPB_ASCII = 0x0202,
  TASK_FULLSCRAPE_TPB_ASCII_PLUS = 0x0203,
  TASK_FULLSCRAPE_TPB_URLENCODED = 0x0204,
  TASK_FULLSCRAPE_TRACKERSTATE = 0x0205,
  TASK_FULLSCRAPE_NDJSON = 0x0206,

  TASK_DMEM = 0x0300,

  TASK_DONE = 0x0f00,
  TASK_DONE_PARTIAL = 0x0f01,

  TASK_FLAG_GZIP = 0x1000,
  TASK_FLAG_BZIP2 = 0x2000,
  TASK_FLAG_ZSTD = 0x4000,
  TASK_FLAG_CHUNKED = 0x8000,

  TASK_TASK_MASK = 0x0fff,
  TASK_CLASS_MASK = 0x0f00,
  TASK_FLAGS_MASK = 0xf000
} ot_tasktype;

typedef unsigned long ot_taskid;

int workqueue_pushquery(int64_t sock, ot_tasktype type, const struct catalog_query *query);
ot_taskid workqueue_popquery(ot_tasktype *type, struct catalog_query *query);
int workqueue_pushtask(int64_t sock, ot_tasktype tasktype);
void workqueue_canceltask(int64_t sock);
void workqueue_pushsuccess(ot_taskid taskid);
ot_taskid workqueue_poptask(ot_tasktype *tasktype);
int workqueue_pushresult(ot_taskid taskid, size_t iovec_entries, struct iovec *iovector);
int workqueue_pushchunked(ot_taskid taskid, struct iovec *iovec);
int64_t workqueue_popresult(size_t *iovec_entries, struct iovec **iovector, int *is_partial);

void workqueue_init(void);
void workqueue_deinit(void);
void workqueue_wakeall(void);

#endif

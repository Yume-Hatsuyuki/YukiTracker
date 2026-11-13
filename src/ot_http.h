/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_HTTP_H__
#define OT_HTTP_H__

#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "ot_batch.h"
#include "ot_event.h"
#include "ot_buf.h"
#include "trackerlogic.h"

typedef enum {
  STRUCT_HTTP_FLAG_WAITINGFORTASK = 1,
  STRUCT_HTTP_FLAG_GZIP = 2,
  STRUCT_HTTP_FLAG_BZIP2 = 4,
  STRUCT_HTTP_FLAG_ZSTD = 8,
  STRUCT_HTTP_FLAG_CHUNKED = 16,
  STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER = 32,
  STRUCT_HTTP_FLAG_KEEPALIVE = 64,
  STRUCT_HTTP_FLAG_JSON = 512,
  STRUCT_HTTP_FLAG_NDJSON = 256,
  STRUCT_HTTP_FLAG_ONSTACK = 128
} STRUCT_HTTP_FLAG;

struct http_data {
  ot_buf request;
  int interest;
  ot_batch *batch;
  ot_ip6 ip;
  STRUCT_HTTP_FLAG flag;
};

void http_interest_set(const int64_t s, struct http_data *cookie, int what);

void http_close(const int64_t s);

struct http_data *http_adopt(const int64_t s);

ssize_t http_handle_request(const int64_t s, struct ot_workstruct *ws);
ssize_t http_sendiovecdata(const int64_t s, struct ot_workstruct *ws, size_t iovec_entries, struct iovec *iovector,
                           int is_partial);
ssize_t http_issue_error(const int64_t s, struct ot_workstruct *ws, int code);

void http_export_init(void);
void http_export_deinit(void);

extern const char *g_stats_path;
extern ssize_t g_stats_path_len;

#endif

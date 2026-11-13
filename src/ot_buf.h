/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_BUF_H__
#define OT_BUF_H__

#include <stddef.h>

typedef struct {
  char *data;
  size_t size;
} ot_buf;

int buf_cat(ot_buf *buf, const void *src, size_t len);

void buf_truncate(ot_buf *buf, size_t len);

void buf_reset(ot_buf *buf);

#endif

/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <stdlib.h>
#include <string.h>

#include "ot_buf.h"

int buf_cat(ot_buf *buf, const void *src, size_t len) {
  char *data;

  if (!len)
    return 0;

  if (buf->size + len < buf->size)
    return -1;

  if (!(data = realloc(buf->data, buf->size + len)))
    return -1;

  buf->data = data;
  memcpy(data + buf->size, src, len);
  buf->size += len;

  return 0;
}

void buf_truncate(ot_buf *buf, size_t len) {
  if (len < buf->size)
    buf->size = len;
}

void buf_reset(ot_buf *buf) {
  free(buf->data);
  buf->data = NULL;
  buf->size = 0;
}

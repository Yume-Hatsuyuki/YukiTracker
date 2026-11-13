/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "ot_batch.h"

#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

#define OT_BATCH_MIN_ENTRIES 16

static int batch_room_for(ot_batch *batch, size_t wanted) {
  size_t space = batch->space ? batch->space : OT_BATCH_MIN_ENTRIES;
  struct iovec *grown;

  if (batch->count + wanted <= batch->space)
    return 0;

  if (batch->first && batch->count - batch->first + wanted <= batch->space) {
    memmove(batch->entries, batch->entries + batch->first, (batch->count - batch->first) * sizeof(struct iovec));
    batch->count -= batch->first;
    batch->first = 0;
    return 0;
  }

  while (space < batch->count + wanted)
    space *= 2;

  if (!(grown = realloc(batch->entries, space * sizeof(struct iovec))))
    return -1;

  batch->entries = grown;
  batch->space = space;
  return 0;
}

int batch_add(ot_batch *batch, void *buf, size_t len) {
  if (batch_room_for(batch, 1)) {
    free(buf);
    return -1;
  }

  batch->entries[batch->count].iov_base = buf;
  batch->entries[batch->count].iov_len = len;
  ++batch->count;
  return 0;
}

int batch_add_vector(ot_batch *batch, const struct iovec *entries, size_t count) {
  if (batch_room_for(batch, count)) {
    while (count--)
      free(entries[count].iov_base);
    return -1;
  }

  memcpy(batch->entries + batch->count, entries, count * sizeof(struct iovec));
  batch->count += count;
  return 0;
}

static void batch_consume(ot_batch *batch, size_t written) {
  while (written) {
    struct iovec *entry = batch->entries + batch->first;
    size_t left = entry->iov_len - batch->offset;

    if (written < left) {
      batch->offset += written;
      return;
    }

    free(entry->iov_base);
    written -= left;
    batch->offset = 0;
    ++batch->first;
  }

  if (batch->first == batch->count)
    batch->first = batch->count = 0;
}

static ssize_t batch_writev(int s, struct iovec *entries, int count) {
#ifdef MSG_NOSIGNAL
  struct msghdr msg;

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = entries;
  msg.msg_iovlen = count;
  return sendmsg(s, &msg, MSG_NOSIGNAL);
#else
  return writev(s, entries, count);
#endif
}

ssize_t batch_send(int s, ot_batch *batch) {
  size_t entries = batch->count - batch->first;
  ssize_t written;

  if (!batch_pending(batch))
    return BATCH_DONE;

  if (entries > IOV_MAX)
    entries = IOV_MAX;

  batch->entries[batch->first].iov_base = (char *)batch->entries[batch->first].iov_base + batch->offset;
  batch->entries[batch->first].iov_len -= batch->offset;
  written = batch_writev(s, batch->entries + batch->first, (int)entries);
  batch->entries[batch->first].iov_base = (char *)batch->entries[batch->first].iov_base - batch->offset;
  batch->entries[batch->first].iov_len += batch->offset;

  if (written < 0)
    return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? BATCH_AGAIN : BATCH_FAILED;
  if (!written)
    return BATCH_FAILED;

  batch_consume(batch, (size_t)written);
  return written;
}

void batch_reset(ot_batch *batch) {
  while (batch->first < batch->count)
    free(batch->entries[batch->first++].iov_base);

  free(batch->entries);
  batch->entries = NULL;
  batch->count = batch->first = batch->offset = batch->space = 0;
}

int batch_add_copy(ot_batch *batch, const void *buf, size_t len) {
  void *copy = malloc(len);

  if (!copy)
    return -1;
  memcpy(copy, buf, len);
  return batch_add(batch, copy, len);
}

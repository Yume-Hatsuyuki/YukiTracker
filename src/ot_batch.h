/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_BATCH_H__
#define OT_BATCH_H__

#include <stddef.h>
#include <sys/types.h>
#include <sys/uio.h>

typedef struct {
  struct iovec *entries;
  size_t space;
  size_t count;
  size_t first;
  size_t offset;
} ot_batch;

static inline int batch_pending(const ot_batch *batch) { return batch->first != batch->count; }

enum { BATCH_DONE = 0, BATCH_AGAIN = -1, BATCH_FAILED = -2 };

/* Queue buf and take ownership of it. Returns 0, or -1 having freed buf. */
int batch_add(ot_batch *batch, void *buf, size_t len);

ssize_t batch_send(int s, ot_batch *batch);

/* Queue every entry of a vector, taking ownership of each buffer but not of
   the vector itself. Returns 0, or -1 having freed all of them. */
int batch_add_vector(ot_batch *batch, const struct iovec *entries, size_t count);

int batch_add_copy(ot_batch *batch, const void *buf, size_t len);

void batch_reset(ot_batch *batch);

#endif

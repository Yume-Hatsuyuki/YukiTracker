/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_IOVEC_H__
#define OT_IOVEC_H__

#include <sys/uio.h>

void *iovec_new_chunk(size_t *iovec_entries, struct iovec **iovector, size_t new_alloc);
void *iovec_append(size_t *iovec_entries, struct iovec **iovector, struct iovec *append_iovector);
void iovec_trim_last(size_t *iovec_entries, struct iovec **iovector, void *last_ptr);
void iovec_free(size_t *iovec_entries, struct iovec **iovector);

size_t iovec_length(const size_t *iovec_entries, const struct iovec **iovector);

void *iovec_next_chunk(size_t *iovec_entries, struct iovec **iovector, void *last_ptr, size_t new_alloc);

#endif

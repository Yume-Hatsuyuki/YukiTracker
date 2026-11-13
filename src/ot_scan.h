/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_SCAN_H__
#define OT_SCAN_H__

#include <stddef.h>
#include <stddef.h>
#include <stdint.h>

size_t scan_uint(const char *src, uint64_t *dest, uint64_t max);

size_t scan_uint_bencode(const char *src, uint64_t *dest, uint64_t max);

int scan_int(const char *src, size_t len, int64_t *dest);

#endif

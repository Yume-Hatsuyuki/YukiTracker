/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_RANDOM_H__
#define OT_RANDOM_H__

#include <stddef.h>
#include <stdint.h>

void random_init(void);

uint32_t random_uint32(void);
void random_bytes(void *buf, size_t len);

#endif

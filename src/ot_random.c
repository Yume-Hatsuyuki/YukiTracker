/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <stdint.h>
#include <stdlib.h>

#include "ot_random.h"

#ifdef WANT_INSECURE_RANDOM_FALLBACK

#warning WANT_INSECURE_RANDOM_FALLBACK builds without arc4random. UDP connection ids become predictable and announces can be forged. Do not ship this.

#include <time.h>

void random_init(void) {
#ifdef WANT_DEV_RANDOM
  srandomdev();
#else
  srandom(time(NULL));
#endif
}

uint32_t random_uint32(void) { return ((uint32_t)random() << 16) ^ (uint32_t)random(); }

void random_bytes(void *buf, size_t len) {
  uint8_t *out = buf;

  while (len--)
    *out++ = (uint8_t)(random() >> 8);
}

#else

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) && !defined(__DragonFly__) &&               \
    !defined(__APPLE__) && !(defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 36)))
#include <bsd/stdlib.h>
#endif

void random_init(void) {}

uint32_t random_uint32(void) { return arc4random(); }

void random_bytes(void *buf, size_t len) { arc4random_buf(buf, len); }

#endif

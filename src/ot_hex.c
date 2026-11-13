/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <stdint.h>
#include <string.h>

#include "ot_hex.h"

int hex_value(int c) {
  unsigned char u = (unsigned char)c;

  if (u >= '0' && u <= '9')
    return u - '0';
  u |= 0x20;
  if (u >= 'a' && u <= 'f')
    return u - 'a' + 10;
  return -1;
}

int hex_isdigit(int c) { return hex_value(c) >= 0; }

char *hex_from_hash(char *dest, const uint8_t *hash) {
  static const char digits[] = "0123456789ABCDEF";
  char *d = dest;
  size_t i;

  for (i = 0; i < sizeof(ot_hash); ++i) {
    *d++ = digits[hash[i] >> 4];
    *d++ = digits[hash[i] & 15];
  }
  *d = 0;
  return dest;
}

int hex_to_hash(ot_hash hash, const char *src) {
  uint8_t decoded[sizeof(ot_hash)];
  size_t i;

  for (i = 0; i < sizeof(ot_hash); ++i) {
    int high, low;

    if ((high = hex_value((unsigned char)src[2 * i])) < 0)
      return 0;
    if ((low = hex_value((unsigned char)src[2 * i + 1])) < 0)
      return 0;

    decoded[i] = (uint8_t)((high << 4) | low);
  }

  memcpy(hash, decoded, sizeof(decoded));
  return 1;
}

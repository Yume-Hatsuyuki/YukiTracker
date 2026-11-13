/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "ot_scan.h"

size_t scan_uint(const char *src, uint64_t *dest, uint64_t max) {
  unsigned long long value;
  char *end;

  if (*src < '0' || *src > '9')
    return 0;

  errno = 0;
  value = strtoull(src, &end, 10);

  if (errno == ERANGE || value > (unsigned long long)max)
    return 0;

  *dest = (uint64_t)value;
  return (size_t)(end - src);
}

size_t scan_uint_bencode(const char *src, uint64_t *dest, uint64_t max) {
  uint64_t value;
  size_t consumed = scan_uint(src, &value, max);

  /* bencode writes no leading zeros, so anything longer than a single digit
     must not begin with one. */
  if (consumed > 1 && *src == '0')
    return 0;

  if (consumed)
    *dest = value;

  return consumed;
}

int scan_int(const char *src, size_t len, int64_t *dest) {
  int64_t value = 0;
  int negate = 0;

  if (len && *src == '-')
    --len, ++src, negate = 1;
  if (!len)
    return -1;

  while (len--) {
    if (*src < '0' || *src > '9')
      return -1;

    if (value > (INT64_MAX - (*src - '0')) / 10)
      return -1;
    value = 10 * value + (*src++ - '0');
  }

  *dest = negate ? -value : value;
  return 0;
}

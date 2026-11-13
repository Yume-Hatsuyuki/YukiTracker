/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <stdint.h>
#include <string.h>

#include "ot_hex.h"
#include "ot_ip.h"

const char ip_v4mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

static size_t ip4_format(char *dest, const uint8_t *ip) {
  char *d = dest;
  int i;

  for (i = 0; i < 4; ++i) {
    unsigned int octet = ip[i];

    if (i)
      *d++ = '.';
    if (octet >= 100)
      *d++ = (char)('0' + octet / 100);
    if (octet >= 10)
      *d++ = (char)('0' + (octet / 10) % 10);
    *d++ = (char)('0' + octet % 10);
  }

  return (size_t)(d - dest);
}

static size_t ip4_scan(const char *src, uint8_t ip[4]) {
  uint8_t octets[4];
  const char *s = src;
  int i;

  for (i = 0; i < 4; ++i) {
    unsigned int value = 0;
    int digits = 0;

    if (i && *s++ != '.')
      return 0;

    while (*s >= '0' && *s <= '9' && digits < 4) {
      value = value * 10 + (unsigned int)(*s++ - '0');
      ++digits;
    }
    if (!digits || value > 255)
      return 0;

    octets[i] = (uint8_t)value;
  }

  memcpy(ip, octets, sizeof(octets));
  return (size_t)(s - src);
}

static unsigned int group_at(const char *ip, int n) {
  return ((unsigned int)(uint8_t)ip[2 * n] << 8) | (uint8_t)ip[2 * n + 1];
}

size_t ip_format(char *dest, const ot_ip6 ip) {
  static const char hexdigit[] = "0123456789abcdef";
  char *d = dest;
  int best_start = 0, best_len = 0, i = 0;

  if (ip_is_v4mapped(ip))
    return ip4_format(dest, (const uint8_t *)ip + sizeof(ip_v4mapped_prefix));

  /* RFC 5952 4.2: the longest run of zero groups becomes "::", never a run
     of one, and the first of two equal runs wins */
  while (i < 8) {
    int j = i;

    if (group_at(ip, i)) {
      ++i;
      continue;
    }
    while (j < 8 && !group_at(ip, j))
      ++j;
    if (j - i > best_len) {
      best_len = j - i;
      best_start = i;
    }
    i = j;
  }
  if (best_len < 2)
    best_len = 0;

  for (i = 0; i < 8; ++i) {
    unsigned int group;
    int shift = 12;

    if (best_len && i == best_start) {
      *d++ = ':';
      if (i + best_len == 8)
        *d++ = ':';
      i += best_len - 1;
      continue;
    }

    if (i)
      *d++ = ':';

    group = group_at(ip, i);
    while (shift && !(group >> shift))
      shift -= 4; /* RFC 5952 4.1: no leading zeros */
    for (;; shift -= 4) {
      *d++ = hexdigit[(group >> shift) & 15];
      if (!shift)
        break;
    }
  }

  return (size_t)(d - dest);
}

size_t ip_parse(const char *src, ot_ip6 ip) {
  uint8_t prefix[16], suffix[16];
  size_t prefixlen = 0, suffixlen = 0;
  const char *s = src;
  int have_gap = 0;
  int need_colon = 0;

  {
    size_t consumed = ip4_scan(src, prefix);
    if (consumed) {
      memcpy(ip, ip_v4mapped_prefix, sizeof(ip_v4mapped_prefix));
      memcpy(ip + sizeof(ip_v4mapped_prefix), prefix, 4);
      return consumed;
    }
  }

  for (;;) {
    unsigned int value = 0;
    int digits = 0, nibble;
    uint8_t *into = have_gap ? suffix : prefix;
    size_t *fill = have_gap ? &suffixlen : &prefixlen;

    /* RFC 4291 2.2: one run of zero groups may be written "::" */
    if (s[0] == ':' && s[1] == ':') {
      if (have_gap)
        return 0;
      have_gap = 1;
      need_colon = 0;
      s += 2;
      continue;
    }

    if (need_colon) {
      if (*s != ':')
        break;
      ++s;
    }

    /* RFC 4291 2.2 form 3: the final two groups may be a dotted quad */
    if (prefixlen + suffixlen + 4 <= 16) {
      size_t consumed = ip4_scan(s, into + *fill);
      if (consumed) {
        *fill += 4;
        s += consumed;
        break;
      }
    }

    while (digits < 4 && (nibble = hex_value(*s)) >= 0) {
      value = value * 16 + (unsigned int)nibble;
      ++digits;
      ++s;
    }
    if (!digits) {
      if (need_colon)
        --s;
      break;
    }

    if (prefixlen + suffixlen + 2 > 16)
      return 0;

    into[(*fill)++] = (uint8_t)(value >> 8);
    into[(*fill)++] = (uint8_t)value;
    need_colon = 1;
  }

  if (!prefixlen && !suffixlen && !have_gap)
    return 0;
  if (!have_gap && prefixlen + suffixlen != 16)
    return 0;

  memset(ip, 0, 16);
  memcpy(ip, prefix, prefixlen);
  memcpy(ip + 16 - suffixlen, suffix, suffixlen);

  return (size_t)(s - src);
}

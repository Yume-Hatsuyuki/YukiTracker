/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include "ot_urlencoded.h"

#include <string.h>

static const unsigned char is_unreserved[256] = {
    8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 7, 8, 8, 8,
    7, 0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 4, 7, 6, 4, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 7, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static unsigned char fromhex(unsigned char x) {
  x -= '0';
  if (x <= 9)
    return x;
  x &= ~0x20;
  x -= 'A' - '0';
  if (x < 6)
    return x + 10;
  return 0xff;
}

void urlencoded_skip_value(char **string) {
  const unsigned char *s = *(const unsigned char **)string;
  unsigned char f;

  while ((f = is_unreserved[*s++]) & SCAN_SEARCHPATH_VALUE)
    ;

  if (f & SCAN_SEARCHPATH_TERMINATOR)
    --s;

  *string = (char *)s;
}

int urlencoded_match_keyword(const ot_keywords *keywords, char **string, const char *deststring_end,
                             SCAN_SEARCHPATH_FLAG flags) {
  char *deststring = *string;
  ssize_t match_length = urlencoded_parse(string, deststring, deststring_end, flags);

  if (match_length < 0)
    return match_length;
  if (match_length == 0)
    return -3;

  while (keywords->key) {
    if ((size_t)match_length == strlen(keywords->key) && !memcmp(keywords->key, deststring, (size_t)match_length))
      return keywords->value;
    keywords++;
  }

  return -3;
}

ssize_t urlencoded_parse(char **string, char *deststring, const char *deststring_end, SCAN_SEARCHPATH_FLAG flags) {
  const unsigned char *s = *(const unsigned char **)string;
  unsigned char *d = (unsigned char *)deststring;
  unsigned char b, c;

  while (is_unreserved[c = *s++] & flags) {

    if (c == '%') {
      if ((b = fromhex(*s++)) == 0xff)
        return -1;
      if ((c = fromhex(*s++)) == 0xff)
        return -1;
      c |= (b << 4);
    }

    if ((const char *)d >= deststring_end)
      return -1;

    *d++ = c;
  }

  switch (c) {
  case 0:
  case '\r':
  case '\n':
  case ' ':

    if (d == (unsigned char *)deststring)
      return -2;

    --s;
    break;
  case '?':
    if (flags != SCAN_PATH)
      return -1;
    break;
  case '=':
    if (flags != SCAN_SEARCHPATH_PARAM)
      return -1;
    break;
  case '&':
    if (flags == SCAN_PATH)
      return -1;
    if (flags == SCAN_SEARCHPATH_PARAM)
      --s;
    break;
  default:
    return -1;
  }

  *string = (char *)s;
  return d - (unsigned char *)deststring;
}

size_t urlencoded_format(char *dest, const uint8_t *src, size_t len) {
  static const char safe[] = "$/.=~-_";
  static const char hexdigit[] = "0123456789abcdef";
  size_t written = 0, i;

  for (i = 0; i < len; ++i) {
    uint8_t c = src[i];

    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c && strchr(safe, c))) {
      dest[written++] = (char)c;
    } else {
      dest[written] = '%';
      dest[written + 1] = hexdigit[c >> 4];
      dest[written + 2] = hexdigit[c & 15];
      written += 3;
    }
  }

  return written;
}

/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ot_fmt.h"

void fmt_append(char **cursor, const char *end, const char *format, ...) {
  va_list arguments;
  size_t room;
  int written;

  if (*cursor >= end) {
    *cursor = (char *)end;
    return;
  }

  room = (size_t)(end - *cursor);
  va_start(arguments, format);
  written = vsnprintf(*cursor, room, format, arguments);
  va_end(arguments);

  if (written < 0)
    return;
  *cursor = (size_t)written >= room ? (char *)end : *cursor + written;
}

void fmt_bytes(char **cursor, const char *end, const void *bytes, size_t length) {
  if (*cursor >= end || (size_t)(end - *cursor) < length) {
    *cursor = (char *)end;
    return;
  }

  memcpy(*cursor, bytes, length);
  *cursor += length;
}

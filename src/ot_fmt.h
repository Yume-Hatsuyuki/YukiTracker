/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_FMT_H__
#define OT_FMT_H__

#include <stddef.h>

void fmt_append(char **cursor, const char *end, const char *format, ...) __attribute__((format(printf, 3, 4)));

void fmt_bytes(char **cursor, const char *end, const void *bytes, size_t length);

#endif

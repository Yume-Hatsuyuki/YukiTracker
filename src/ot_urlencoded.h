/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef SCAN_URLENCODED_QUERY_H__
#define SCAN_URLENCODED_QUERY_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
  const char *key;
  int value;
} ot_keywords;

typedef enum {
  SCAN_PATH = 1,
  SCAN_SEARCHPATH_PARAM = 2,
  SCAN_SEARCHPATH_VALUE = 4,
  SCAN_SEARCHPATH_TERMINATOR = 8
} SCAN_SEARCHPATH_FLAG;

ssize_t urlencoded_parse(char **string, char *deststring, const char *deststring_end, SCAN_SEARCHPATH_FLAG flags);

int urlencoded_match_keyword(const ot_keywords *keywords, char **string, const char *deststring_end,
                             SCAN_SEARCHPATH_FLAG flags);

void urlencoded_skip_value(char **string);

size_t urlencoded_format(char *dest, const uint8_t *src, size_t len);

#endif

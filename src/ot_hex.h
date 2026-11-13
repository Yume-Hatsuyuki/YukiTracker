/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_HEX_H__
#define OT_HEX_H__

#include <stdint.h>

#include "trackerlogic.h"

char *hex_from_hash(char *dest, const uint8_t *hash);

int hex_to_hash(ot_hash hash, const char *src);

int hex_isdigit(int c);

int hex_value(int c);

#endif

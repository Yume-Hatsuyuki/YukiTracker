/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_IP_H__
#define OT_IP_H__

#include <stddef.h>
#include <string.h>

#include "trackerlogic.h"

/* the tracker holds every address as sixteen bytes, writing IPv4 as the v4
   mapped form of RFC 4291 section 2.5.5.2. */
extern const char ip_v4mapped_prefix[12];

static inline int ip_is_v4mapped(const void *ip) { return !memcmp(ip, ip_v4mapped_prefix, sizeof(ip_v4mapped_prefix)); }

size_t ip_parse(const char *src, ot_ip6 ip);

size_t ip_format(char *dest, const ot_ip6 ip);

#endif

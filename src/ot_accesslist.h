/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_ACCESSLIST_H__
#define OT_ACCESSLIST_H__

#include "trackerlogic.h"

#if defined(WANT_ACCESSLIST_BLACK) && defined(WANT_ACCESSLIST_WHITE)
#error WANT_ACCESSLIST_BLACK and WANT_ACCESSLIST_WHITE are exclusive.
#endif

#if defined(WANT_ACCESSLIST_BLACK) || defined(WANT_ACCESSLIST_WHITE)
#define WANT_ACCESSLIST

void accesslist_init(void);
void accesslist_deinit(void);
int accesslist_hashisvalid(const ot_hash hash);
void accesslist_cleanup(void);

size_t accesslist_parse_hashes(ot_hash *dest, size_t capacity, const char *buf, size_t len);

extern const char *g_accesslist_filename;
extern int g_whitelist;
#ifdef WANT_DYNAMIC_ACCESSLIST
extern const char *g_accesslist_pipe_add;
extern const char *g_accesslist_pipe_delete;
#endif

#else
#ifdef WANT_DYNAMIC_ACCESSLIST
#error WANT_DYNAMIC_ACCESSLIST needs either WANT_ACCESSLIST_BLACK or WANT_ACCESSLIST_WHITE
#endif

#define accesslist_init(accesslist_filename)
#define accesslist_deinit()
#define accesslist_hashisvalid(hash) 1
#endif

int accesslist_address_in_net(const ot_ip6 address, const ot_net *net);

void *accesslist_set_value_for_net(const ot_net *net, ot_vector *vector, const void *value, const size_t member_size);

void *accesslist_get_value_for_net(const ot_ip6 address, const ot_vector *vector, const size_t member_size);

#ifdef WANT_IP_FROM_PROXY
int proxylist_add_network(const ot_net *proxy, const ot_net *net);
int proxylist_check_network(const ot_ip6 *proxy, const ot_ip6 address);
#endif

typedef enum {
  OT_PERMISSION_MAY_FULLSCRAPE = 0x1,
  OT_PERMISSION_MAY_STAT = 0x2,
  OT_PERMISSION_MAY_LIVESYNC = 0x4,
  OT_PERMISSION_DIAG = 16,
  OT_PERMISSION_RECORD = 32,
  OT_PERMISSION_MAY_PROXY = 0x8
} ot_permissions;

int accesslist_bless_net(ot_net *net, ot_permissions permissions);
int accesslist_is_blessed(const ot_ip6 ip, ot_permissions permissions);

#endif

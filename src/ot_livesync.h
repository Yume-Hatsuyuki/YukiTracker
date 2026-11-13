/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
 It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_LIVESYNC_H__
#define OT_LIVESYNC_H__

#include "trackerlogic.h"

#ifdef WANT_SYNC_LIVE

#define LIVESYNC_PORT 9696

void livesync_init(void);
void livesync_deinit(void);

int livesync_set_group(const ot_ip6 group);

void livesync_bind_mcast(ot_ip6 ip, uint16_t port);

void livesync_tell(struct ot_workstruct *ws);

void livesync_ticker(void);

void handle_livesync(const int64_t sock);

#else

#define livesync_deinit()
#define livesync_init()
#define livesync_ticker()
#define handle_livesync(a)

#endif

#endif

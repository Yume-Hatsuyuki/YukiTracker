/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_UDP_H__
#define OT_UDP_H__

#include <stdint.h>

#include "trackerlogic.h"

void udp_init(void);

void udp_worker_install(int64_t sock);

int handle_udp6(int64_t serversocket, struct ot_workstruct *ws);

#endif

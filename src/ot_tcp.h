/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_TCP_H__
#define OT_TCP_H__

#include <stdint.h>

#include "trackerlogic.h"

void tcp_accept(const int64_t serversocket, struct ot_workstruct *ws);

void tcp_read(const int64_t sock, struct ot_workstruct *ws);
void tcp_write(const int64_t sock);

void tcp_worker_install(int64_t sock);

#endif

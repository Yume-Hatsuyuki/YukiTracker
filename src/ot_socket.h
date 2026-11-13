/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_SOCKET_H__
#define OT_SOCKET_H__

#include <stdint.h>
#include <sys/types.h>

#include "trackerlogic.h"

typedef enum { SOCKET_EXCLUSIVE, SOCKET_SHARED, SOCKET_BALANCED } socket_sharing;

int socket_can_balance(void);

int socket_tcp_listen(const ot_ip6 ip, uint16_t port, socket_sharing sharing);
int socket_udp_bind(const ot_ip6 ip, uint16_t port, socket_sharing sharing);

int socket_tcp_connect(const ot_ip6 srcip, uint16_t srcport, const ot_ip6 dstip, uint16_t dstport);
int socket_is_connected(int s);
int socket_accept(int s, ot_ip6 ip, uint16_t *port);
int socket_set_blocking(int s, int blocking);
int socket_defer_accept(int s);

ssize_t socket_recv(int s, void *buf, size_t len, ot_ip6 ip, uint16_t *port);
ssize_t socket_send(int s, const void *buf, size_t len, const ot_ip6 ip, uint16_t port);

#ifdef WANT_SYNC_LIVE

int socket_mcast_join(const ot_ip6 group, const ot_ip6 interface, uint16_t port);
int socket_mcast_bind(const ot_ip6 interface, uint16_t port, int loopback);
ssize_t socket_mcast_send(int s, const void *buf, size_t len, const ot_ip6 group, uint16_t port);
#endif

#endif

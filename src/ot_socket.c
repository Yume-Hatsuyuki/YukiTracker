/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ot_ip.h"
#include "ot_socket.h"

static void sockaddr_from_ip(struct sockaddr_in6 *sa, const ot_ip6 ip, uint16_t port) {
  memset(sa, 0, sizeof(*sa));
  sa->sin6_family = AF_INET6;
  sa->sin6_port = htons(port);
  memcpy(&sa->sin6_addr, ip, sizeof(ot_ip6));
}

static void ip_from_sockaddr(ot_ip6 ip, uint16_t *port, const struct sockaddr_storage *ss) {
  if (ss->ss_family == AF_INET) {
    const struct sockaddr_in *sa = (const struct sockaddr_in *)ss;

    memcpy(ip, ip_v4mapped_prefix, sizeof(ip_v4mapped_prefix));
    memcpy(ip + sizeof(ip_v4mapped_prefix), &sa->sin_addr, 4);
    *port = ntohs(sa->sin_port);
  } else {
    const struct sockaddr_in6 *sa = (const struct sockaddr_in6 *)ss;

    memcpy(ip, &sa->sin6_addr, sizeof(ot_ip6));
    *port = ntohs(sa->sin6_port);
  }
}

int socket_set_blocking(int s, int blocking) {
  int flags = fcntl(s, F_GETFL, 0);

  if (flags == -1)
    return -1;
  return fcntl(s, F_SETFL, blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK));
}

static int set_nonblocking(int s) { return socket_set_blocking(s, 0); }

static int close_and_fail(int s) {
  int saved = errno;
  close(s);
  errno = saved;
  return -1;
}

static int socket_v6(int type) {
  int s = socket(PF_INET6, type, 0);
  int zero = 0;

  if (s == -1)
    return -1;

  if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero)) == -1)
    return close_and_fail(s);

  if (set_nonblocking(s) == -1)
    return close_and_fail(s);

  return s;
}

#if defined(SO_REUSEPORT_LB)
#define OT_BALANCE_OPTION SO_REUSEPORT_LB
#elif defined(SO_REUSEPORT) && !defined(__APPLE__)
#define OT_BALANCE_OPTION SO_REUSEPORT
#endif

int socket_can_balance(void) {
#ifdef OT_BALANCE_OPTION
  return 1;
#else
  return 0;
#endif
}

static void socket_set_sharing(int s, socket_sharing sharing) {
  int one = 1;

  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef OT_BALANCE_OPTION
  if (sharing == SOCKET_BALANCED) {
    setsockopt(s, SOL_SOCKET, OT_BALANCE_OPTION, &one, sizeof(one));
    return;
  }
#endif
#ifdef SO_REUSEPORT
  if (sharing != SOCKET_EXCLUSIVE)
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
}

static int socket_bind_v6(int s, const ot_ip6 ip, uint16_t port, socket_sharing sharing) {
  struct sockaddr_in6 sa;

  socket_set_sharing(s, sharing);

  sockaddr_from_ip(&sa, ip, port);
  return bind(s, (struct sockaddr *)&sa, sizeof(sa));
}

int socket_defer_accept(int s) {
#if defined(TCP_DEFER_ACCEPT)
  int patience = g_http_read_timeout;

  return setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &patience, sizeof(patience));
#elif defined(SO_ACCEPTFILTER)
  struct accept_filter_arg filter;
  const char name[sizeof(filter.af_name)] = "dataready";

  memset(&filter, 0, sizeof(filter));
  memcpy(filter.af_name, name, sizeof(name));
  return setsockopt(s, SOL_SOCKET, SO_ACCEPTFILTER, &filter, sizeof(filter));
#else
  (void)s;
  return -1;
#endif
}

int socket_tcp_listen(const ot_ip6 ip, uint16_t port, socket_sharing sharing) {
  int s = socket_v6(SOCK_STREAM);

  if (s == -1)
    return -1;
  if (socket_bind_v6(s, ip, port, sharing) == -1 || listen(s, SOMAXCONN) == -1)
    return close_and_fail(s);

  return s;
}

int socket_udp_bind(const ot_ip6 ip, uint16_t port, socket_sharing sharing) {
  int s = socket_v6(SOCK_DGRAM);

  if (s == -1)
    return -1;
  if (socket_bind_v6(s, ip, port, sharing) == -1)
    return close_and_fail(s);

  return s;
}

int socket_tcp_connect(const ot_ip6 srcip, uint16_t srcport, const ot_ip6 dstip, uint16_t dstport) {
  struct sockaddr_in6 sa;
  int s = socket_v6(SOCK_STREAM);

  if (s == -1)
    return -1;
  if (socket_bind_v6(s, srcip, srcport, SOCKET_EXCLUSIVE) == -1)
    return close_and_fail(s);

  sockaddr_from_ip(&sa, dstip, dstport);
  if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == -1 && errno != EINPROGRESS && errno != EWOULDBLOCK)
    return close_and_fail(s);

  return s;
}

int socket_is_connected(int s) {
  int error = 0;
  socklen_t len = sizeof(error);

  if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) == -1)
    return 0;
  if (error) {
    errno = error;
    return 0;
  }
  return 1;
}

int socket_accept(int s, ot_ip6 ip, uint16_t *port) {
  struct sockaddr_storage ss;
  socklen_t len = sizeof(ss);
  int fd;

  memset(&ss, 0, sizeof(ss));
#ifdef SOCK_NONBLOCK
  if ((fd = accept4(s, (struct sockaddr *)&ss, &len, SOCK_NONBLOCK)) == -1)
    return -1;
#else
  if ((fd = accept(s, (struct sockaddr *)&ss, &len)) == -1)
    return -1;
  if (set_nonblocking(fd) == -1)
    return close_and_fail(fd);
#endif

  ip_from_sockaddr(ip, port, &ss);
  return fd;
}

ssize_t socket_recv(int s, void *buf, size_t len, ot_ip6 ip, uint16_t *port) {
  struct sockaddr_storage ss;
  socklen_t sslen = sizeof(ss);
  ssize_t received;

  memset(&ss, 0, sizeof(ss));
  received = recvfrom(s, buf, len, 0, (struct sockaddr *)&ss, &sslen);
  if (received == -1)
    return -1;

  ip_from_sockaddr(ip, port, &ss);
  return received;
}

ssize_t socket_send(int s, const void *buf, size_t len, const ot_ip6 ip, uint16_t port) {
  struct sockaddr_in6 sa;

  sockaddr_from_ip(&sa, ip, port);
  return sendto(s, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
}

#ifdef WANT_SYNC_LIVE
static void sockaddr4_from_ip(struct sockaddr_in *sa, const ot_ip6 ip, uint16_t port) {
  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;
  sa->sin_port = htons(port);
  memcpy(&sa->sin_addr, ip + sizeof(ip_v4mapped_prefix), 4);
}

static int socket_v4_bind(const ot_ip6 ip, uint16_t port) {
  struct sockaddr_in sa;
  int s;

  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
    return -1;

  socket_set_sharing(s, SOCKET_SHARED);

  sockaddr4_from_ip(&sa, ip, port);
  if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    return close_and_fail(s);

  return s;
}

int socket_mcast_join(const ot_ip6 group, const ot_ip6 interface, uint16_t port) {
  struct ip_mreq mreq;
  int s;

  if ((s = socket_v4_bind(group, port)) == -1)
    return -1;

  memset(&mreq, 0, sizeof(mreq));
  memcpy(&mreq.imr_multiaddr, group + sizeof(ip_v4mapped_prefix), 4);
  memcpy(&mreq.imr_interface, interface + sizeof(ip_v4mapped_prefix), 4);
  if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1)
    return close_and_fail(s);

  return s;
}

int socket_mcast_bind(const ot_ip6 interface, uint16_t port, int loopback) {

  unsigned char ttl = 1, loop = (unsigned char)(loopback != 0);
  int s = socket_v4_bind(interface, port);

  if (s == -1)
    return -1;
  if (set_nonblocking(s) == -1)
    return close_and_fail(s);

  if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1 ||
      setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) == -1)
    return close_and_fail(s);

  return s;
}

ssize_t socket_mcast_send(int s, const void *buf, size_t len, const ot_ip6 group, uint16_t port) {
  struct sockaddr_in sa;

  sockaddr4_from_ip(&sa, group, port);
  return sendto(s, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
}
#endif

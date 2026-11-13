/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ot_ip.h"
#include "ot_random.h"
#include "ot_rijndael.h"
#include "ot_socket.h"
#include "ot_worker.h"
#include "ot_stats.h"
#include "ot_udp.h"
#include "trackerlogic.h"

static uint32_t g_rijndael_round_key[44] = {0};
static _Atomic uint32_t g_key_of_the_hour[2] = {0};
static _Atomic ot_time g_hour_of_the_key;
static pthread_mutex_t key_lock = PTHREAD_MUTEX_INITIALIZER;

static void udp_generate_rijndael_round_key(void) {
  uint32_t key[16];
  random_bytes(key, sizeof(key));
  rijndaelKeySetupEnc128(g_rijndael_round_key, (uint8_t *)key);

  g_key_of_the_hour[0] = random_uint32();
  g_hour_of_the_key = time_now_minutes();
}

static void udp_make_connectionid(uint32_t connid[2], const ot_ip6 remoteip, int age) {
  uint32_t plain[4], crypt[4];
  int i;
  uint32_t current_key_of_the_hour;

  if (time_since_minutes(g_hour_of_the_key) >= g_key_minutes) {
    pthread_mutex_lock(&key_lock);
    if (time_since_minutes(g_hour_of_the_key) >= g_key_minutes) {
      g_key_of_the_hour[1] = g_key_of_the_hour[0];
      g_key_of_the_hour[0] = random_uint32();
      g_hour_of_the_key = time_now_minutes();
    }
    pthread_mutex_unlock(&key_lock);
  }

  memcpy(plain, remoteip, sizeof(plain));
  current_key_of_the_hour = g_key_of_the_hour[age];
  for (i = 0; i < 4; ++i)
    plain[i] ^= current_key_of_the_hour;
  rijndaelEncrypt128(g_rijndael_round_key, (uint8_t *)plain, (uint8_t *)crypt);
  connid[0] = crypt[0] ^ crypt[1];
  connid[1] = crypt[2] ^ crypt[3];
}

int handle_udp6(int64_t serversocket, struct ot_workstruct *ws) {
  ot_ip6 remoteip;
  uint32_t *inpacket = (uint32_t *)ws->inbuf;
  uint32_t *outpacket = (uint32_t *)ws->outbuf;
  uint32_t left, event;
  uint32_t connid[2];
  uint32_t action;
  uint16_t port, remoteport;
  size_t byte_count, scrape_count;

  ssize_t result = socket_recv(serversocket, ws->inbuf, G_INBUF_SIZE, remoteip, &remoteport);
  if (result <= 0)
    return 0;
  byte_count = (size_t)result;

  stats_issue_event(ws, EVENT_ACCEPT, FLAG_UDP, (uintptr_t)remoteip);
  stats_issue_event(ws, EVENT_READ, FLAG_UDP, byte_count);

  if (byte_count < 16)
    return 1;

  action = ntohl(inpacket[2]);
  if (action > 2)
    return 1;

  udp_make_connectionid(connid, remoteip, 0);

  ws->hash = NULL;
  ws->peer_id = NULL;

  if ((action > 0) && (inpacket[0] != connid[0] || inpacket[1] != connid[1])) {

    udp_make_connectionid(connid, remoteip, 1);
    if (inpacket[0] != connid[0] || inpacket[1] != connid[1]) {
      const char err_idmiss[] = "Connection ID missmatch.";
      size_t s = sizeof(err_idmiss);
      outpacket[0] = htonl(3);
      outpacket[1] = inpacket[3];
      memcpy(&outpacket[2], &err_idmiss[0], s);
      socket_send(serversocket, ws->outbuf, 8 + s, remoteip, remoteport);
      stats_issue_event(ws, EVENT_CONNID_MISSMATCH, FLAG_UDP, 8 + s);
      return 1;
    }
  }

  switch (action) {
  case 0:

    if ((ntohl(inpacket[0]) != 0x00000417) || (ntohl(inpacket[1]) != 0x27101980))
      return 1;

    outpacket[0] = 0;
    outpacket[1] = inpacket[3];
    outpacket[2] = connid[0];
    outpacket[3] = connid[1];

    socket_send(serversocket, ws->outbuf, 16, remoteip, remoteport);
    stats_issue_event(ws, EVENT_CONNECT, FLAG_UDP, 16);
    break;
  case 1:

    if (byte_count < 98)
      return 1;

    left = inpacket[64 / 4] | inpacket[68 / 4];

    event = ntohl(inpacket[80 / 4]);
    port = *(uint16_t *)(((char *)inpacket) + 96);
    ws->hash = (ot_hash *)(((char *)inpacket) + 16);

    OT_SETIP(ws->peer, remoteip);
    OT_SETPORT(ws->peer, &port);
    OT_PEERFLAG(ws->peer) = 0;

    switch (event) {
    case 1:
      OT_PEERFLAG(ws->peer) |= PEER_FLAG_COMPLETED;
      break;
    case 3:
      OT_PEERFLAG(ws->peer) |= PEER_FLAG_STOPPED;
      break;
    default:
      break;
    }

    if (!left)
      OT_PEERFLAG(ws->peer) |= PEER_FLAG_SEEDING;

    outpacket[0] = htonl(1);
    outpacket[1] = inpacket[12 / 4];

    if (OT_PEERFLAG(ws->peer) & PEER_FLAG_STOPPED) {
      ws->reply = ws->outbuf;
      ws->reply_size = remove_peer_from_torrent(FLAG_UDP, ws);
    } else {

      uint32_t numwant = ntohl(inpacket[92 / 4]);
      size_t max_peers = ip_is_v4mapped(remoteip) ? g_max_udp4 : g_max_udp6;
      if (numwant == UINT32_MAX)
        numwant = g_default_numwant;
      if (numwant > max_peers)
        numwant = max_peers;

      ws->reply = ws->outbuf + 8;
      ws->reply_size = add_peer_to_torrent_and_return_peers(FLAG_UDP, ws, numwant);

      if (!ws->reply_size) {
        const char err_resources[] = "Tracker is out of resources, try again later.";
        size_t s = sizeof(err_resources);
        outpacket[0] = htonl(3);
        memcpy(&outpacket[2], &err_resources[0], s);
        socket_send(serversocket, ws->outbuf, 8 + s, remoteip, remoteport);
        return 1;
      }
      ws->reply_size += 8;
    }

    socket_send(serversocket, ws->outbuf, ws->reply_size, remoteip, remoteport);
    stats_issue_event(ws, EVENT_ANNOUNCE, FLAG_UDP, ws->reply_size);
    break;

  case 2:
    outpacket[0] = htonl(2);
    outpacket[1] = inpacket[12 / 4];

    if (byte_count == 16 || (byte_count - 16) % 20 || (byte_count - 16) / 20 > (size_t)g_max_scrape_udp) {
      static const char message[] = "Invalid scrape length";
      outpacket[0] = htonl(3);
      memcpy(outpacket + 2, message, sizeof(message) - 1);
      socket_send(serversocket, ws->outbuf, 8 + sizeof(message) - 1, remoteip, remoteport);
      return 1;
    }
    for (scrape_count = 0; scrape_count < (byte_count - 16) / 20; scrape_count++)
      return_udp_scrape_for_torrent(*(ot_hash *)(((char *)inpacket) + 16 + 20 * scrape_count),
                                    ((char *)outpacket) + 8 + 12 * scrape_count);

    socket_send(serversocket, ws->outbuf, 8 + 12 * scrape_count, remoteip, remoteport);
    stats_issue_event(ws, EVENT_SCRAPE, FLAG_UDP, scrape_count);
    break;
  }
  return 1;
}

static void udp_run(struct ot_worker *me) {
  while (tracker_running)
    handle_udp6(me->sock, &me->ws);
}

void udp_init(void) {
  if (!g_rijndael_round_key[0])
    udp_generate_rijndael_round_key();
}

void udp_worker_install(int64_t sock) {
  socket_set_blocking((int)sock, 1);

  if (worker_start(udp_run, sock) == -1)
    fprintf(stderr, "Warning: could not install a udp worker, this socket stays with the workers already running.\n");
}

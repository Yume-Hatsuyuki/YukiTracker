/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
 It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ot_accesslist.h"
#include "ot_ip.h"
#include "ot_socket.h"
#include "ot_livesync.h"
#include "ot_mutex.h"
#include "ot_stats.h"
#include "trackerlogic.h"

#ifdef WANT_SYNC_LIVE

static ot_ip6 g_group = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 224, 0, 23, 5};
static uint16_t g_port = LIVESYNC_PORT;

#define LIVESYNC_INCOMING_BUFFSIZE (256 * 256)

#define LIVESYNC_OUTGOING_BUFFSIZE_PEERS 1480
#define LIVESYNC_OUTGOING_WATERMARK_PEERS (sizeof(ot_hash) + OT_PEER_SIZE6)

#define LIVESYNC_MAXDELAY 15

enum { OT_SYNC_PEER4, OT_SYNC_PEER6 };

static void *livesync_worker(void *args);

static int g_socket_in = -1;

static int g_socket_out = -1;

static pthread_mutex_t g_outbuf_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
  uint8_t data[LIVESYNC_OUTGOING_BUFFSIZE_PEERS];
  size_t fill;
  ot_time next_packet_time;
} sync_buffer;

static sync_buffer g_v6_buf;
static sync_buffer g_v4_buf;

static pthread_t thread_id;
static int thread_started;
static _Atomic int thread_left;
void livesync_init(void) {
  uint32_t packet_type6 = htonl(OT_SYNC_PEER6);
  uint32_t packet_type4 = htonl(OT_SYNC_PEER4);

  if (g_socket_in == -1)
    return;

  memcpy(g_v6_buf.data, &g_tracker_id, sizeof(g_tracker_id));
  memcpy(g_v4_buf.data, &g_tracker_id, sizeof(g_tracker_id));

  memcpy(g_v6_buf.data + sizeof(g_tracker_id), &packet_type6, sizeof(packet_type6));
  memcpy(g_v4_buf.data + sizeof(g_tracker_id), &packet_type4, sizeof(packet_type4));

  g_v6_buf.fill = sizeof(g_tracker_id) + sizeof(uint32_t);
  g_v4_buf.fill = sizeof(g_tracker_id) + sizeof(uint32_t);

  g_v6_buf.next_packet_time = time_future_seconds(LIVESYNC_MAXDELAY);
  g_v4_buf.next_packet_time = time_future_seconds(LIVESYNC_MAXDELAY);

  thread_started = !pthread_create(&thread_id, NULL, livesync_worker, NULL);
}

void livesync_deinit(void) {
  if (thread_started) {

    while (!atomic_load(&thread_left)) {
      pthread_kill(thread_id, OT_SIGNAL_WAKE);
      usleep(1000);
    }
    pthread_join(thread_id, NULL);
    thread_started = 0;
  }

  if (g_socket_in != -1)
    close(g_socket_in);
  if (g_socket_out != -1)
    close(g_socket_out);
}

int livesync_set_group(const ot_ip6 group) {

  if (!ip_is_v4mapped(group) || (group[12] & 0xf0) != 0xe0)
    return -1;
  memcpy(g_group, group, sizeof(ot_ip6));
  return 0;
}

void livesync_bind_mcast(ot_ip6 ip, uint16_t port) {
  if (!ip_is_v4mapped(ip))
    exerr("v6 mcast support not yet available.");

  if (g_socket_in != -1)
    exerr("Error: Livesync listen ip specified twice.");

  g_port = port;

  if ((g_socket_in = socket_mcast_join(g_group, ip, port)) == -1)
    exerr("Error: Cant bind live sync incoming socket.");

  if ((g_socket_out = socket_mcast_bind(ip, port, 0)) == -1)
    exerr("Error: Cant bind live sync outgoing socket.");
}

/* Caller MUST hold g_outbuf_mutex. Returns with g_outbuf_mutex unlocked */
static void livesync_issue_peersync(sync_buffer *buf) {
  char mycopy[LIVESYNC_OUTGOING_BUFFSIZE_PEERS];
  size_t fill = buf->fill;

  if (fill > LIVESYNC_OUTGOING_BUFFSIZE_PEERS)
    fill = LIVESYNC_OUTGOING_BUFFSIZE_PEERS;

  memcpy(mycopy, buf->data, fill);
  buf->fill = sizeof(g_tracker_id) + sizeof(uint32_t);
  buf->next_packet_time = time_future_seconds(LIVESYNC_MAXDELAY);

  pthread_mutex_unlock(&g_outbuf_mutex);

  socket_mcast_send(g_socket_out, mycopy, fill, g_group, g_port);
}

static void livesync_handle_peersync(struct ot_workstruct *ws, size_t peer_size) {
  size_t off = sizeof(g_tracker_id) + sizeof(uint32_t);

  if (peer_size == OT_PEER_SIZE4)
    memcpy(&ws->peer, ip_v4mapped_prefix, sizeof(ip_v4mapped_prefix));

  while ((ssize_t)(off + sizeof(ot_hash) + peer_size) <= ws->request_size) {
    char *peer_ip = ws->request + off + sizeof(ot_hash);
    if (peer_size == OT_PEER_SIZE4)
      memcpy(&ws->peer[0] + sizeof(ip_v4mapped_prefix), peer_ip, peer_size);
    else
      memcpy(&ws->peer, peer_ip, peer_size);
    ws->hash = (ot_hash *)(ws->request + off);

    if (!tracker_running)
      return;

    if (OT_PEERFLAG(ws->peer) & PEER_FLAG_STOPPED)
      remove_peer_from_torrent(FLAG_MCA, ws);
    else
      add_peer_to_torrent_and_return_peers(FLAG_MCA, ws, 0);

    off += sizeof(ot_hash) + peer_size;
  }

  stats_issue_event(ws, EVENT_SYNC, 0,
                    (ws->request_size - sizeof(g_tracker_id) - sizeof(uint32_t)) /
                        ((ssize_t)sizeof(ot_hash) + peer_size));
}

void livesync_ticker(void) {
  if (g_socket_out == -1)
    return;

  pthread_mutex_lock(&g_outbuf_mutex);
  if (time_is_past(g_v6_buf.next_packet_time) && g_v6_buf.fill > sizeof(g_tracker_id) + sizeof(uint32_t))
    livesync_issue_peersync(&g_v6_buf);
  else
    pthread_mutex_unlock(&g_outbuf_mutex);

  pthread_mutex_lock(&g_outbuf_mutex);
  if (time_is_past(g_v4_buf.next_packet_time) && g_v4_buf.fill > sizeof(g_tracker_id) + sizeof(uint32_t))
    livesync_issue_peersync(&g_v4_buf);
  else
    pthread_mutex_unlock(&g_outbuf_mutex);
}

void livesync_tell(struct ot_workstruct *ws) {
  size_t peer_size;
  ot_peer *peer_src;
  sync_buffer *dest_buf;

  if (g_socket_out == -1)
    return;

  peer_src = peer_from_peer6(&ws->peer, &peer_size);
  dest_buf = peer_size == OT_PEER_SIZE6 ? &g_v6_buf : &g_v4_buf;

  pthread_mutex_lock(&g_outbuf_mutex);

  memcpy(dest_buf->data + dest_buf->fill, ws->hash, sizeof(ot_hash));
  dest_buf->fill += sizeof(ot_hash);

  memcpy(dest_buf->data + dest_buf->fill, peer_src, peer_size);
  dest_buf->fill += peer_size;

  if (dest_buf->fill >= LIVESYNC_OUTGOING_BUFFSIZE_PEERS - LIVESYNC_OUTGOING_WATERMARK_PEERS)
    livesync_issue_peersync(dest_buf);
  else
    pthread_mutex_unlock(&g_outbuf_mutex);
}

static void *livesync_worker(void *args) {
  struct ot_workstruct ws;
  ot_ip6 in_ip;
  uint16_t in_port;

  (void)args;

  if (workstruct_init(&ws, LIVESYNC_INCOMING_BUFFSIZE) == -1) {
    fprintf(stderr, "Warning: live sync could not get its buffers and will not run.\n");
    atomic_store(&thread_left, 1);
    return NULL;
  }
  ws.request = ws.inbuf;

  while (tracker_running) {
    uint32_t packet_type;

    ws.request_size = socket_recv(g_socket_in, ws.inbuf, LIVESYNC_INCOMING_BUFFSIZE, in_ip, &in_port);

    if (ws.request_size <= (ssize_t)(sizeof(g_tracker_id) + sizeof(uint32_t)))
      continue;
    if (!accesslist_is_blessed(in_ip, OT_PERMISSION_MAY_LIVESYNC))
      continue;
    if (!memcmp(ws.inbuf, &g_tracker_id, sizeof(g_tracker_id))) {

      continue;
    }

    memcpy(&packet_type, ws.inbuf + sizeof(g_tracker_id), sizeof(packet_type));

    switch (ntohl(packet_type)) {
    case OT_SYNC_PEER6:
      livesync_handle_peersync(&ws, OT_PEER_SIZE6);
      break;
    case OT_SYNC_PEER4:
      livesync_handle_peersync(&ws, OT_PEER_SIZE4);
      break;
    default:
      break;
    }
  }

  workstruct_deinit(&ws);
  atomic_store(&thread_left, 1);
  return NULL;
}

#endif

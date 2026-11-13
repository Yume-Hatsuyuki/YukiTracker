/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ot_batch.h"
#include "ot_buf.h"
#include "ot_event.h"
#include "ot_fdstate.h"
#include "ot_http.h"
#include "ot_mutex.h"
#include "ot_socket.h"
#include "ot_worker.h"
#include "ot_stats.h"
#include "ot_tcp.h"
#include "trackerlogic.h"

static ssize_t header_complete(char *request, ssize_t byte_count) {
  ssize_t i = 0, state = 0;

  for (i = 1; i < byte_count; i += 2)
    if (request[i] <= 13) {
      i--;
      for (state = 0; i < byte_count; ++i) {
        char c = request[i];
        if (c == '\r' || c == '\n')
          state = (state >> 2) | ((c << 6) & 0xc0);
        else
          break;
        if (state >= 0xa0 || state == 0x99)
          return i + 1;
      }
    }
  return 0;
}

void tcp_read(const int64_t sock, struct ot_workstruct *ws) {
  struct http_data *cookie = fdstate_cookie(sock);
  ssize_t byte_count = read((int)sock, ws->inbuf, G_INBUF_SIZE);
  uint32_t generation;

  if (byte_count == 0 || (byte_count == -1 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
    http_close(sock);
    return;
  }

  if (byte_count == -1)
    return;

  ws->request = NULL;
  ws->request_size = 0;
  ws->header_size = 0;
  ws->keep_alive = 0;

  if (!cookie->request.data) {
    if ((ws->header_size = header_complete(ws->inbuf, byte_count))) {
      ws->request = ws->inbuf;
      ws->request_size = byte_count;
      http_handle_request(sock, ws);
    } else if (buf_cat(&cookie->request, ws->inbuf, (size_t)byte_count))
      http_close(sock);
    return;
  }

  if (buf_cat(&cookie->request, ws->inbuf, (size_t)byte_count) || cookie->request.size > G_INBUF_SIZE) {
    http_issue_error(sock, ws, CODE_HTTPERROR_500);
    return;
  }

  generation = fdstate_generation((int)sock);
  while ((ws->header_size = header_complete(cookie->request.data, (ssize_t)cookie->request.size))) {
    ws->request = cookie->request.data;
    ws->request_size = (ssize_t)cookie->request.size;
    http_handle_request(sock, ws);

    if (ws->handed_off)
      return;

    if (fdstate_generation((int)sock) != generation)
      return;
#ifdef WANT_KEEPALIVE
    if (!ws->keep_alive)
#endif
      return;
  }
}

void tcp_write(const int64_t sock) {
  struct http_data *cookie = fdstate_cookie(sock);
  int chunked = 0;
  int keep_alive = 0;

  if (cookie) {
    chunked = (cookie->flag & STRUCT_HTTP_FLAG_CHUNKED_IN_TRANSFER) != 0;
    keep_alive = (cookie->flag & STRUCT_HTTP_FLAG_KEEPALIVE) != 0;

    if (cookie->batch) {
      if (batch_send(sock, cookie->batch) == BATCH_FAILED) {
        http_close(sock);
        return;
      }
      if (batch_pending(cookie->batch))
        return;
    }
  }

  if (chunked)
    http_interest_set(sock, cookie, 0);
  else if (keep_alive) {

    http_interest_set(sock, cookie, EVENT_IN);
    fdstate_set_expiry(sock, time_future_seconds(g_http_read_timeout));
  } else
    http_close(sock);
}

void tcp_accept(const int64_t serversocket, struct ot_workstruct *ws) {
  int64_t sock;
  ot_ip6 ip;
  uint16_t port;

  while ((sock = socket_accept(serversocket, ip, &port)) != -1) {
    struct http_data cookie;
    uint32_t generation;

    memset(&cookie, 0, sizeof(cookie));
    memcpy(cookie.ip, ip, sizeof(ot_ip6));
    cookie.interest = EVENT_IN;
    cookie.flag = STRUCT_HTTP_FLAG_ONSTACK;

    generation = fdstate_open(sock, &cookie, time_future_seconds(g_http_read_timeout));
    if (!fdstate_claim((int)sock, generation)) {
      fdstate_close(sock);
      event_close((int)sock);
      continue;
    }

    stats_issue_event(ws, EVENT_ACCEPT, FLAG_TCP, (uintptr_t)ip);

    tcp_read(sock, ws);

    if (fdstate_generation((int)sock) != generation)
      continue;

    if (fdstate_cookie((int)sock) != &cookie)
      fdstate_release((int)sock);
    else if (!http_adopt(sock))
      http_close(sock);
    else
      fdstate_release((int)sock);
  }
}

static void tcp_run(struct ot_worker *me) {
  while (tracker_running)
    tcp_accept(me->sock, &me->ws);
}

void tcp_worker_install(int64_t sock) {
  socket_set_blocking((int)sock, 1);
  socket_defer_accept((int)sock);

  if (worker_start(tcp_run, sock) == -1)
    fprintf(stderr, "Warning: could not install a tcp worker, this socket stays with the workers already running.\n");
}

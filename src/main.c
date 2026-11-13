/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever.
   Some of the stuff below is stolen from Fefes example libowfat httpd. */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef WANT_SYSLOGS
#include <syslog.h>
#endif

#include "ot_accesslist.h"
#include "ot_config.h"
#include "ot_hex.h"
#include "state_snapshot.h"
#include "diagnostics.h"
#include "ot_http.h"
#include "ot_ip.h"
#include "ot_livesync.h"
#include "ot_mutex.h"
#include "ot_workqueue.h"
#include "ot_random.h"
#include "ot_scan.h"
#include "ot_event.h"
#include "ot_fdstate.h"
#include "ot_socket.h"
#include "ot_stats.h"
#include "ot_tcp.h"
#include "ot_udp.h"
#include "ot_worker.h"
#include "trackerlogic.h"

uint32_t g_tracker_id;
_Atomic int tracker_running = 1;
int g_self_pipe[2];

static void panic(const char *routine) __attribute__((noreturn));
static void panic(const char *routine) {
  fprintf(stderr, "%s: %s\n", routine, strerror(errno));
  exit(111);
}

static void signal_handler(int s) {
  if (s == SIGINT || s == SIGTERM) {
    const char byte = 0;
    int saved = errno;

    signal(s, SIG_DFL);

    tracker_running = 0;

    (void)!write(g_self_pipe[1], &byte, 1);
    errno = saved;
  }
}

static void defaul_signal_handlers(void) {
  sigset_t signal_mask;
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGPIPE);
  sigaddset(&signal_mask, SIGHUP);
  sigaddset(&signal_mask, SIGINT);
  sigaddset(&signal_mask, SIGTERM);
  sigaddset(&signal_mask, SIGALRM);
  pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
}

static void install_signal_handlers(void) {
  struct sigaction sa;
  sigset_t signal_mask;
  sigemptyset(&signal_mask);

  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if ((sigaction(SIGINT, &sa, NULL) == -1) || (sigaction(SIGTERM, &sa, NULL) == -1) ||
      (sigaction(SIGALRM, &sa, NULL) == -1) || (sigaction(OT_SIGNAL_WAKE, &sa, NULL) == -1))
    panic("install_signal_handlers");

  sigaddset(&signal_mask, SIGINT);
  sigaddset(&signal_mask, SIGTERM);
  pthread_sigmask(SIG_UNBLOCK, &signal_mask, NULL);
}

#define OT_EVENT_BATCH 512

static void *server_mainloop(void *args) {
  struct ot_workstruct ws;
  time_t next_timeout_check = time_future_seconds(OT_CLIENT_TIMEOUT_CHECKINTERVAL);
  struct iovec *iovector;
  size_t iovec_entries;
  int is_partial;

  (void)args;

  if (workstruct_init(&ws, G_INBUF_SIZE) == -1)
    panic("Initializing worker failed");

  while (tracker_running) {
    ot_event ready[OT_EVENT_BATCH];
    int64_t sock;
    int count, i;

    count = event_wait(ready, OT_EVENT_BATCH, OT_CLIENT_TIMEOUT_CHECKINTERVAL * 1000);

    for (i = 0; i < count; ++i) {
      const void *cookie;

      sock = ready[i].fd;

      if (fdstate_generation((int)sock) != ready[i].generation)
        continue;
      cookie = fdstate_cookie((int)sock);

      if ((intptr_t)cookie == FLAG_TCP)
        tcp_accept(sock, &ws);
      else if ((intptr_t)cookie == FLAG_UDP)
        handle_udp6(sock, &ws);
      else if ((intptr_t)cookie == FLAG_SELFPIPE)
        while (read((int)sock, ws.inbuf, G_INBUF_SIZE) > 0)
          ;
      else if (fdstate_claim((int)sock, ready[i].generation)) {
        if (ready[i].what & EVENT_IN)
          tcp_read(sock, &ws);

        if ((ready[i].what & EVENT_OUT) && fdstate_generation((int)sock) == ready[i].generation)
          tcp_write(sock);
        if (fdstate_generation((int)sock) == ready[i].generation)
          fdstate_release((int)sock);
      }
    }

    while ((sock = workqueue_popresult(&iovec_entries, &iovector, &is_partial)) != -1)
      http_sendiovecdata(sock, &ws, iovec_entries, iovector, is_partial);

    if (time_is_past(next_timeout_check)) {
      int cursor = 0;

      while ((sock = fdstate_next_expired(time_now_seconds(), &cursor)) != -1)
        http_close(sock);
      next_timeout_check = time_future_seconds(OT_CLIENT_TIMEOUT_CHECKINTERVAL);
    }

    livesync_ticker();
  }

  workstruct_deinit(&ws);
  return 0;
}

static socket_sharing listen_sharing_for(const ot_listen *entry) {
  if (entry->proto != FLAG_MCA && entry->workers > 1 && socket_can_balance())
    return SOCKET_BALANCED;
  return entry->shared ? SOCKET_SHARED : SOCKET_EXCLUSIVE;
}

static void listen_bind_one(ot_listen *entry) {
  socket_sharing sharing = listen_sharing_for(entry);

#ifdef WANT_SYNC_LIVE
  if (entry->proto == FLAG_MCA) {
    livesync_bind_mcast(entry->ip, entry->port);
    return;
  }
#endif

  if (entry->proto == FLAG_TCP) {
    if ((entry->sock = socket_tcp_listen(entry->ip, entry->port, sharing)) == -1)
      panic("socket_tcp_listen");
    socket_defer_accept((int)entry->sock);
  } else {
    if ((entry->sock = socket_udp_bind(entry->ip, entry->port, sharing)) == -1)
      panic("socket_udp_bind");
  }

  if (event_add((int)entry->sock, EVENT_IN, fdstate_open(entry->sock, (void *)entry->proto, 0)) == -1)
    panic("event_add");
}

static void listen_bind_all(void) {
  size_t count, i;
  ot_listen *entries = config_listen_entries(&count);

  for (i = 0; i < count; ++i)
    listen_bind_one(entries + i);
}

static void listen_start_tcp_workers(void) {
  size_t count, i;
  ot_listen *entries = config_listen_entries(&count);

  for (i = 0; i < count; ++i) {
    ot_listen *entry = entries + i;
    int balance = listen_sharing_for(entry) == SOCKET_BALANCED;
    int worker;

    if (entry->proto != FLAG_TCP || entry->workers <= 0)
      continue;

    event_del((int)entry->sock);
    tcp_worker_install(entry->sock);

    for (worker = 1; worker < entry->workers; ++worker) {
      int64_t sock = entry->sock;

      if (balance) {
        sock = socket_tcp_listen(entry->ip, entry->port, SOCKET_BALANCED);
        if (sock == -1) {
          fprintf(stderr, "Warning: could not bind another socket for tcp worker %d: %s. Sharing the first instead.\n",
                  worker, strerror(errno));
          sock = entry->sock;
        }
      }
      tcp_worker_install(sock);
    }
  }
}

static void listen_start_udp_workers(void) {
  size_t count, i;
  ot_listen *entries = config_listen_entries(&count);

  udp_init();

  for (i = 0; i < count; ++i) {
    ot_listen *entry = entries + i;
    int balance = listen_sharing_for(entry) == SOCKET_BALANCED;
    int worker;

    if (entry->proto != FLAG_UDP || entry->workers <= 0)
      continue;

    event_del((int)entry->sock);
    udp_worker_install(entry->sock);

    for (worker = 1; worker < entry->workers; ++worker) {
      int64_t sock = entry->sock;

      if (balance) {
        sock = socket_udp_bind(entry->ip, entry->port, SOCKET_BALANCED);
        if (sock == -1) {
          fprintf(stderr, "Warning: could not bind another socket for udp worker %d: %s. Sharing the first instead.\n",
                  worker, strerror(errno));
          sock = entry->sock;
        }
      }
      udp_worker_install(sock);
    }
  }
}

void load_state(const char *const state_filename) {
  FILE *state_filehandle;
  char inbuf[512];
  ot_hash infohash;
  uint64_t touched, downcount;
  int consumed;

  uint64_t now = (uint64_t)time_wall_minutes();

  state_filehandle = fopen(state_filename, "r");

  if (state_filehandle == NULL) {
    fprintf(stderr, "Warning: Can't open config file: %s.", state_filename);
    return;
  }

  while (fgets(inbuf, sizeof(inbuf), state_filehandle)) {
    size_t i;

    if (!hex_to_hash(infohash, inbuf))
      continue;
    i = 2 * sizeof(ot_hash);

    if (inbuf[i++] != ':' || !(consumed = scan_uint(inbuf + i, &touched, now)))
      continue;
    i += consumed;
    if (inbuf[i++] != ':' || !(consumed = scan_uint(inbuf + i, &downcount, SIZE_MAX)))
      continue;
    add_torrent_from_saved_state(infohash, (ot_time)(now - touched), (size_t)downcount);
  }

  fclose(state_filehandle);
}

int drop_privileges(const char *const serveruser, const char *const serverdir) {
  struct passwd *pws = NULL;

  pws = getpwnam(serveruser);
  endpwent();

  if (geteuid() == 0) {

    if (serverdir && chroot(serverdir)) {
      fprintf(stderr, "Could not chroot to %s, because: %s\n", serverdir, strerror(errno));
      return -1;
    }

    if (chdir("/"))
      panic("chdir() failed after chrooting: ");

    if (!pws) {
      fprintf(stderr, "Warning: Could not get password entry for %s. Reverting to uid -2.\n", serveruser);
      if (setgroups(0, NULL) || setegid((gid_t)-2) || setgid((gid_t)-2) || setuid((uid_t)-2) || seteuid((uid_t)-2))
        panic("Could not set uid to value -2");
    } else {
      if (setgroups(0, NULL) || setegid(pws->pw_gid) || setgid(pws->pw_gid) || setuid(pws->pw_uid) ||
          seteuid(pws->pw_uid))
        panic("Could not set uid to specified value");
    }

    if (geteuid() == 0 || getegid() == 0)
      panic("Still running with root privileges?!");
  } else {

    if (serverdir && chdir(serverdir)) {
      fprintf(stderr, "Could not chroot to %s, because: %s\n", serverdir, strerror(errno));
      return -1;
    }
  }

  return 0;
}

int main(int argc, char **argv) {

  random_init();
  if (fdstate_init() == -1)
    panic("fdstate_init");
  if (event_init() == -1)
    panic("event_init");
  config_parse(argc, argv);

  listen_bind_all();

  defaul_signal_handlers();

#ifdef WANT_SYSLOGS
  openlog("yukitracker", 0, LOG_USER);
  setlogmask(LOG_UPTO(LOG_INFO));
#endif

  if (drop_privileges(g_serveruser ? g_serveruser : "nobody", g_serverdir) == -1)
    panic("drop_privileges failed, exiting. Last error");

  if (pipe(g_self_pipe) == -1)
    panic("selfpipe failed: ");

  socket_set_blocking(g_self_pipe[0], 0);
  socket_set_blocking(g_self_pipe[1], 0);
  if (event_add(g_self_pipe[0], EVENT_IN, fdstate_open(g_self_pipe[0], (void *)FLAG_SELFPIPE, 0)) == -1)
    panic("selfpipe event_add");

  install_signal_handlers();

  http_export_init();
  diag_start();
  trackerlogic_init();

  state_snapshot_start(g_snapshot, g_save_period);
  if (g_statefile)
    load_state(g_statefile);

  livesync_init();
  listen_start_tcp_workers();
  listen_start_udp_workers();

  server_mainloop(0);
  worker_stop_all();
  livesync_deinit();

  int snapshot_failed = state_snapshot_stop();
  if (snapshot_failed)
    perror("Final state snapshot");
  trackerlogic_deinit();
  diag_stop();
  http_export_deinit();
#ifdef WANT_SYSLOGS
  closelog();
#endif

  event_deinit();
  fdstate_deinit();
  return snapshot_failed ? 1 : 0;
}

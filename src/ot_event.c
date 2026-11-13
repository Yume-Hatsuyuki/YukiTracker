/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ot_event.h"

#if defined(OT_EVENT_FORCE_POLL)
#define OT_EVENT_POLL
#elif defined(OT_EVENT_FORCE_KQUEUE)
#define OT_EVENT_KQUEUE
#elif defined(__linux__)
#define OT_EVENT_EPOLL
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) ||                 \
    defined(__APPLE__)
#define OT_EVENT_KQUEUE
#else
#define OT_EVENT_POLL
#endif

#ifdef OT_EVENT_EPOLL

#include <sys/epoll.h>

static int g_epoll = -1;
static struct epoll_event *g_ready;
static int g_ready_space;

const char *event_mechanism(void) { return "epoll"; }

int event_can_share(void) { return 1; }

int event_init(void) {
  g_ready = NULL;
  g_ready_space = 0;
  return (g_epoll = epoll_create1(EPOLL_CLOEXEC)) == -1 ? -1 : 0;
}

void event_deinit(void) {
  if (g_epoll != -1)
    close(g_epoll);
  free(g_ready);
  g_epoll = -1;
  g_ready = NULL;
  g_ready_space = 0;
}

static int event_ctl(int op, int fd, int what, uint32_t generation) {
  struct epoll_event ev;

  memset(&ev, 0, sizeof(ev));
  ev.events = (what & EVENT_IN ? (uint32_t)EPOLLIN : 0) | (what & EVENT_OUT ? (uint32_t)EPOLLOUT : 0);

  ev.data.u64 = ((uint64_t)generation << 32) | (uint32_t)fd;
  return epoll_ctl(g_epoll, op, fd, &ev);
}

int event_add(int fd, int what, uint32_t generation) { return event_ctl(EPOLL_CTL_ADD, fd, what, generation); }
int event_modify(int fd, int what, uint32_t generation) { return event_ctl(EPOLL_CTL_MOD, fd, what, generation); }
int event_del(int fd) { return epoll_ctl(g_epoll, EPOLL_CTL_DEL, fd, NULL); }

int event_close(int fd) { return close(fd); }

int event_wait(ot_event *out, int max, int timeout_ms) {
  int count, i;

  if (max > g_ready_space) {
    struct epoll_event *grown = realloc(g_ready, (size_t)max * sizeof(struct epoll_event));

    if (!grown)
      return -1;
    g_ready = grown;
    g_ready_space = max;
  }

  if ((count = epoll_wait(g_epoll, g_ready, max, timeout_ms)) == -1)
    return errno == EINTR ? 0 : -1;
  for (i = 0; i < count; ++i) {
    uint32_t events = g_ready[i].events;

    out[i].fd = (int)(uint32_t)g_ready[i].data.u64;
    out[i].generation = (uint32_t)(g_ready[i].data.u64 >> 32);

    out[i].what = (events & (EPOLLIN | EPOLLHUP | EPOLLERR) ? EVENT_IN : 0) |
                  (events & (EPOLLOUT | EPOLLHUP | EPOLLERR) ? EVENT_OUT : 0);
  }
  return count;
}

#endif

#ifdef OT_EVENT_KQUEUE

#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>

static int g_kqueue = -1;
static struct kevent *g_ready;
static int g_ready_space;

const char *event_mechanism(void) { return "kqueue"; }

int event_can_share(void) { return 1; }

int event_init(void) {
  g_ready = NULL;
  g_ready_space = 0;
  return (g_kqueue = kqueue()) == -1 ? -1 : 0;
}

void event_deinit(void) {
  if (g_kqueue != -1)
    close(g_kqueue);
  free(g_ready);
  g_kqueue = -1;
  g_ready = NULL;
  g_ready_space = 0;
}

static int event_change(int fd, int what, uint32_t generation, int deleting) {
  struct kevent change[2], result[2];
  void *udata = (void *)(uintptr_t)(((uint64_t)generation << 32) | (uint32_t)fd);
  int succeeded = 0, count, i;

  EV_SET(&change[0], (uintptr_t)fd, EVFILT_READ, EV_RECEIPT | ((deleting || !(what & EVENT_IN)) ? EV_DELETE : EV_ADD),
         0, 0, udata);
  EV_SET(&change[1], (uintptr_t)fd, EVFILT_WRITE, EV_RECEIPT | ((deleting || !(what & EVENT_OUT)) ? EV_DELETE : EV_ADD),
         0, 0, udata);

  if ((count = kevent(g_kqueue, change, 2, result, 2, NULL)) == -1)
    return -1;

  for (i = 0; i < count && i < 2; ++i) {
    if (!result[i].data) {
      ++succeeded;
      continue;
    }

    if ((change[i].flags & EV_DELETE) && result[i].data == ENOENT)
      continue;
    errno = (int)result[i].data;
    return -1;
  }

  if (!succeeded) {
    errno = ENOENT;
    return -1;
  }
  return 0;
}

int event_add(int fd, int what, uint32_t generation) { return what ? event_change(fd, what, generation, 0) : 0; }
int event_modify(int fd, int what, uint32_t generation) { return event_change(fd, what, generation, 0); }
int event_del(int fd) { return event_change(fd, 0, 0, 1); }

int event_close(int fd) { return close(fd); }

int event_wait(ot_event *out, int max, int timeout_ms) {
  struct timespec timeout;
  struct timespec *deadline = NULL;
  int count, i;

  if (max > g_ready_space) {
    struct kevent *grown = realloc(g_ready, (size_t)max * sizeof(struct kevent));

    if (!grown)
      return -1;
    g_ready = grown;
    g_ready_space = max;
  }

  if (timeout_ms >= 0) {
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_nsec = (long)(timeout_ms % 1000) * 1000000;
    deadline = &timeout;
  }

  if ((count = kevent(g_kqueue, NULL, 0, g_ready, max, deadline)) == -1)
    return errno == EINTR ? 0 : -1;
  for (i = 0; i < count; ++i) {
    uint64_t udata = (uint64_t)(uintptr_t)g_ready[i].udata;
    int eof = (g_ready[i].flags & (EV_EOF | EV_ERROR)) != 0;

    out[i].fd = (int)(uint32_t)udata;
    out[i].generation = (uint32_t)(udata >> 32);
    out[i].what = ((g_ready[i].filter == EVFILT_READ || eof) ? EVENT_IN : 0) |
                  ((g_ready[i].filter == EVFILT_WRITE || eof) ? EVENT_OUT : 0);
  }
  return count;
}

#endif

#ifdef OT_EVENT_POLL

#include <poll.h>

static struct pollfd *g_pfds;
static uint32_t *g_generation;
static int *g_where;
static int g_count, g_space, g_where_space;

const char *event_mechanism(void) { return "poll"; }

int event_can_share(void) { return 0; }

int event_init(void) {
  g_pfds = NULL, g_generation = NULL, g_where = NULL;
  g_count = g_space = g_where_space = 0;
  return 0;
}

void event_deinit(void) {
  free(g_pfds), free(g_generation), free(g_where);
  g_pfds = NULL, g_generation = NULL, g_where = NULL;
  g_count = g_space = g_where_space = 0;
}

static short event_to_poll(int what) {
  return (short)((what & EVENT_IN ? POLLIN : 0) | (what & EVENT_OUT ? POLLOUT : 0));
}

static int event_room_for(int fd) {
  if (fd >= g_where_space) {
    int space = g_where_space ? g_where_space : 64;
    int *grown;

    while (space <= fd)
      space *= 2;
    if (!(grown = realloc(g_where, (size_t)space * sizeof(int))))
      return -1;
    while (g_where_space < space)
      grown[g_where_space++] = -1;
    g_where = grown;
  }

  if (g_count == g_space) {
    int space = g_space ? g_space * 2 : 64;
    struct pollfd *pfds = realloc(g_pfds, (size_t)space * sizeof(struct pollfd));
    uint32_t *gens;

    if (!pfds)
      return -1;
    g_pfds = pfds;
    if (!(gens = realloc(g_generation, (size_t)space * sizeof(uint32_t))))
      return -1;
    g_generation = gens;
    g_space = space;
  }
  return 0;
}

int event_add(int fd, int what, uint32_t generation) {
  if (fd < 0 || event_room_for(fd) == -1)
    return -1;
  if (g_where[fd] != -1) {
    errno = EEXIST;
    return -1;
  }

  g_pfds[g_count].fd = fd;
  g_pfds[g_count].events = event_to_poll(what);
  g_pfds[g_count].revents = 0;
  g_generation[g_count] = generation;
  g_where[fd] = g_count++;
  return 0;
}

int event_modify(int fd, int what, uint32_t generation) {
  if (fd < 0 || fd >= g_where_space || g_where[fd] == -1) {
    errno = ENOENT;
    return -1;
  }
  g_pfds[g_where[fd]].events = event_to_poll(what);
  g_generation[g_where[fd]] = generation;
  return 0;
}

int event_del(int fd) {
  int at;

  if (fd < 0 || fd >= g_where_space || (at = g_where[fd]) == -1) {
    errno = ENOENT;
    return -1;
  }

  g_pfds[at] = g_pfds[--g_count];
  g_generation[at] = g_generation[g_count];
  g_where[g_pfds[at].fd] = at;
  g_where[fd] = -1;
  return 0;
}

int event_close(int fd) {
  event_del(fd);
  return close(fd);
}

int event_wait(ot_event *out, int max, int timeout_ms) {
  int ready, found = 0, i;

  if ((ready = poll(g_pfds, (nfds_t)g_count, timeout_ms)) == -1)
    return errno == EINTR ? 0 : -1;
  if (ready <= 0)
    return ready;

  for (i = 0; i < g_count && found < max; ++i) {
    short revents = g_pfds[i].revents;

    if (!revents)
      continue;
    out[found].fd = g_pfds[i].fd;
    out[found].generation = g_generation[i];
    out[found].what = (revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL) ? EVENT_IN : 0) |
                      (revents & (POLLOUT | POLLHUP | POLLERR | POLLNVAL) ? EVENT_OUT : 0);
    ++found;
  }
  return found;
}

#endif

/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_EVENT_H__
#define OT_EVENT_H__

#include <stdint.h>

enum { EVENT_IN = 1, EVENT_OUT = 2 };

typedef struct {
  int fd;
  uint32_t generation;
  int what;
} ot_event;

int event_init(void);
void event_deinit(void);

int event_add(int fd, int what, uint32_t generation);
int event_modify(int fd, int what, uint32_t generation);
int event_del(int fd);

int event_close(int fd);

int event_wait(ot_event *out, int max, int timeout_ms);

int event_can_share(void);

const char *event_mechanism(void);

#endif

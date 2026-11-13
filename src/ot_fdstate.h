/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifndef OT_FDSTATE_H__
#define OT_FDSTATE_H__

#include <stdint.h>

#include "trackerlogic.h"

int fdstate_init(void);
void fdstate_deinit(void);
size_t fdstate_slots(void);

uint32_t fdstate_open(int fd, void *cookie, ot_time expiry);

uint32_t fdstate_generation(int fd);

int fdstate_claim(int fd, uint32_t generation);
void fdstate_release(int fd);

int fdstate_claim_expired(int fd, ot_time now);

void fdstate_close(int fd);

int fdstate_next_expired(ot_time now, int *cursor);

void *fdstate_cookie(int fd);

void fdstate_set_cookie(int fd, void *cookie);
void fdstate_set_expiry(int fd, ot_time expiry);

#endif

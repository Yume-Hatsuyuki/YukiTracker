/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "ot_fdstate.h"

enum { FD_FREE, FD_IDLE, FD_BUSY, FD_CLOSING };

#define FD_GEN(w) ((uint32_t)((w) >> 32))
#define FD_ST(w) ((uint32_t)(((w) >> 24) & 0xff))
#define FD_WORD(g, s) (((uint64_t)(g) << 32) | ((uint64_t)(s) << 24))
#define FD_SET_ST(w, s) (((w) & ~(uint64_t)0xff000000) | ((uint64_t)(s) << 24))

typedef struct {
  _Atomic uint64_t state;
  _Atomic(void *) cookie;
  _Atomic ot_time expiry;
} ot_fdslot;

#define FD_SLOTS_MAX (1u << 20)

static ot_fdslot *g_slots;
static size_t g_slot_count;

static _Atomic size_t g_slot_highest;

int fdstate_init(void) {
  struct rlimit limit;
  size_t count = FD_SLOTS_MAX;

  if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < FD_SLOTS_MAX)
    count = (size_t)limit.rlim_cur;

  g_slots = mmap(NULL, count * sizeof(ot_fdslot), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (g_slots == MAP_FAILED) {
    g_slots = NULL;
    return -1;
  }

  g_slot_count = count;
  atomic_store(&g_slot_highest, 0);
  return 0;
}

void fdstate_deinit(void) {
  if (g_slots)
    munmap(g_slots, g_slot_count * sizeof(ot_fdslot));
  g_slots = NULL;
  g_slot_count = 0;
  atomic_store(&g_slot_highest, 0);
}

size_t fdstate_slots(void) { return g_slot_count; }

static ot_fdslot *fdstate_slot(int fd) {
  if (fd < 0 || (size_t)fd >= g_slot_count)
    return NULL;
  return g_slots + fd;
}

uint32_t fdstate_open(int fd, void *cookie, ot_time expiry) {
  ot_fdslot *slot = fdstate_slot(fd);
  uint64_t word;

  if (!slot)
    return 0;

  {
    size_t highest = atomic_load_explicit(&g_slot_highest, memory_order_relaxed);

    while ((size_t)fd > highest && !atomic_compare_exchange_weak_explicit(&g_slot_highest, &highest, (size_t)fd,
                                                                          memory_order_relaxed, memory_order_relaxed))
      ;
  }

  word = atomic_load_explicit(&slot->state, memory_order_relaxed);
  atomic_store_explicit(&slot->cookie, cookie, memory_order_release);
  atomic_store_explicit(&slot->expiry, expiry, memory_order_relaxed);

  atomic_store_explicit(&slot->state, FD_WORD(FD_GEN(word), FD_IDLE), memory_order_release);

  return FD_GEN(word);
}

uint32_t fdstate_generation(int fd) {
  ot_fdslot *slot = fdstate_slot(fd);

  return slot ? FD_GEN(atomic_load_explicit(&slot->state, memory_order_relaxed)) : 0;
}

int fdstate_claim(int fd, uint32_t generation) {
  ot_fdslot *slot = fdstate_slot(fd);
  uint64_t word;

  if (!slot)
    return 0;

  word = atomic_load_explicit(&slot->state, memory_order_acquire);
  for (;;) {
    if (FD_GEN(word) != generation || FD_ST(word) != FD_IDLE)
      return 0;
    if (atomic_compare_exchange_weak_explicit(&slot->state, &word, FD_SET_ST(word, FD_BUSY), memory_order_acquire,
                                              memory_order_relaxed))
      return 1;
  }
}

void fdstate_release(int fd) {
  ot_fdslot *slot = fdstate_slot(fd);
  uint64_t word;

  if (!slot)
    return;

  word = atomic_load_explicit(&slot->state, memory_order_relaxed);
  atomic_store_explicit(&slot->state, FD_SET_ST(word, FD_IDLE), memory_order_release);
}

int fdstate_claim_expired(int fd, ot_time now) {
  ot_fdslot *slot = fdstate_slot(fd);
  uint64_t word;
  ot_time expiry;

  if (!slot)
    return 0;

  word = atomic_load_explicit(&slot->state, memory_order_relaxed);
  if (FD_ST(word) != FD_IDLE)
    return 0;
  expiry = atomic_load_explicit(&slot->expiry, memory_order_relaxed);
  if (!expiry || expiry > now)
    return 0;

  return atomic_compare_exchange_strong_explicit(&slot->state, &word, FD_SET_ST(word, FD_CLOSING), memory_order_acquire,
                                                 memory_order_relaxed);
}

void fdstate_close(int fd) {
  ot_fdslot *slot = fdstate_slot(fd);
  uint64_t word;

  if (!slot)
    return;

  word = atomic_load_explicit(&slot->state, memory_order_relaxed);
  atomic_store_explicit(&slot->cookie, NULL, memory_order_relaxed);
  atomic_store_explicit(&slot->expiry, 0, memory_order_relaxed);
  atomic_store_explicit(&slot->state, FD_WORD(FD_GEN(word) + 1, FD_FREE), memory_order_release);
}

int fdstate_next_expired(ot_time now, int *cursor) {
  size_t highest = atomic_load_explicit(&g_slot_highest, memory_order_relaxed);

  for (; (size_t)*cursor <= highest; ++*cursor)
    if (fdstate_claim_expired(*cursor, now))
      return (*cursor)++;

  return -1;
}

void *fdstate_cookie(int fd) {
  ot_fdslot *slot = fdstate_slot(fd);

  return slot ? atomic_load_explicit(&slot->cookie, memory_order_acquire) : NULL;
}

void fdstate_set_cookie(int fd, void *cookie) {
  ot_fdslot *slot = fdstate_slot(fd);

  if (slot)
    atomic_store_explicit(&slot->cookie, cookie, memory_order_release);
}

void fdstate_set_expiry(int fd, ot_time expiry) {
  ot_fdslot *slot = fdstate_slot(fd);

  if (slot)
    atomic_store_explicit(&slot->expiry, expiry, memory_order_relaxed);
}

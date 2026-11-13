#include "diagnostics.h"
#include "ot_fmt.h"
#include "ot_ip.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>

enum { REQUEST_BYTES = 512 };
typedef struct {
  ot_ip6 ip;
  time_t when;
  unsigned len, truncated;
  unsigned char request[REQUEST_BYTES];
} entry;
typedef struct {
  uint32_t key;
  uint64_t count;
} net;
unsigned diag_slots, busy_slots, busy_gap = 20, busy_decay = 120, busy_bits = 24;
static entry *entries;
static net *nets;

static unsigned *heads, *links, *minimum;
static unsigned leaves;
static unsigned hash_bucket(uint32_t key) {
  key ^= key >> 16;
  key *= UINT32_C(0x7feb352d);
  key ^= key >> 15;
  key *= UINT32_C(0x846ca68b);
  return (key ^ (key >> 16)) & (leaves - 1);
}

static unsigned winner(unsigned left, unsigned right) {
  if (left >= busy_slots)
    return right;
  if (right >= busy_slots)
    return left;
  return nets[left].count <= nets[right].count ? left : right;
}

static void rebuild_index(void) {
  memset(heads, 0, leaves * sizeof(*heads));
  for (unsigned i = 0; i < leaves; ++i) {
    minimum[leaves + i] = i;
    if (i < busy_slots && nets[i].count) {
      unsigned bucket = hash_bucket(nets[i].key);
      links[i] = heads[bucket];
      heads[bucket] = i + 1;
    }
  }
  for (unsigned node = leaves - 1; node; --node)
    minimum[node] = winner(minimum[2 * node], minimum[2 * node + 1]);
}

static void update_minimum(unsigned slot) {
  for (unsigned node = (leaves + slot) / 2; node; node /= 2)
    minimum[node] = winner(minimum[2 * node], minimum[2 * node + 1]);
}
static unsigned next, occupied;
static ot_time last_decay;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER, net_lock = PTHREAD_MUTEX_INITIALIZER;

void diag_start(void) {
  if (diag_slots && !(entries = calloc(diag_slots, sizeof(*entries))))
    exerr("Cannot allocate request log");
  if (busy_slots) {
    for (leaves = 1; leaves < busy_slots; leaves *= 2) {
    }
    nets = calloc(busy_slots, sizeof(*nets));
    heads = calloc(leaves, sizeof(*heads));
    links = calloc(busy_slots, sizeof(*links));
    minimum = calloc(2 * leaves, sizeof(*minimum));
    if (!nets || !heads || !links || !minimum)
      exerr("Cannot allocate network counters");
    rebuild_index();
  }
  last_decay = time_now_seconds();
}
void diag_stop(void) {
  free(entries);
  free(nets);
  free(heads);
  free(links);
  free(minimum);
}

void diag_record(const ot_ip6 ip, const char *request, size_t len) {
  pthread_mutex_lock(&log_lock);
  entry *e = &entries[next];
  memcpy(e->ip, ip, 16);
  e->when = time(NULL);
  e->truncated = len > REQUEST_BYTES;
  e->len = e->truncated ? REQUEST_BYTES : (unsigned)len;
  memcpy(e->request, request, e->len);
  next = (next + 1) % diag_slots;
  if (occupied < diag_slots)
    ++occupied;
  pthread_mutex_unlock(&log_lock);
}
static void decay(void) {
  ot_time now = time_now_seconds(), steps = (now - last_decay) / busy_decay;
  if (!steps)
    return;
  for (unsigned i = 0; i < busy_slots; ++i)
    nets[i].count = steps >= 64 ? 0 : nets[i].count >> steps;
  rebuild_index();
  last_decay += steps * busy_decay;
}
void diag_renew(const ot_ip6 ip, unsigned age) {
  if (!age || age >= busy_gap || !ip_is_v4mapped(ip))
    return;
  uint32_t key;
  memcpy(&key, ip + 12, 4);
  key = ntohl(key) & (UINT32_MAX << (32 - busy_bits));
  pthread_mutex_lock(&net_lock);
  decay();
  unsigned bucket = hash_bucket(key);
  unsigned link = heads[bucket];
  while (link && nets[link - 1].key != key)
    link = links[link - 1];
  unsigned slot;
  if (link) {
    slot = link - 1;
    ++nets[slot].count;
  } else {
    slot = minimum[1];
    if (nets[slot].count) {
      unsigned *prev = &heads[hash_bucket(nets[slot].key)];
      while (*prev != slot + 1)
        prev = &links[*prev - 1];
      *prev = links[slot];
    }
    nets[slot] = (net){key, 1};
    links[slot] = heads[bucket];
    heads[bucket] = slot + 1;
  }
  update_minimum(slot);
  pthread_mutex_unlock(&net_lock);
}

size_t diag_render(char *out, size_t cap, int busy, unsigned limit) {
  char *p = out;
  const char *end = out + cap;
  if (busy) {
    net best[128];
    unsigned n = 0, tracked = 0;
    pthread_mutex_lock(&net_lock);
    decay();
    for (unsigned i = 0; i < busy_slots; ++i) {
      if (!nets[i].count)
        continue;
      ++tracked;
      if (n == limit && nets[i].count <= best[n - 1].count)
        continue;
      unsigned j = n == limit ? n - 1 : n++;
      while (j && best[j - 1].count < nets[i].count) {
        best[j] = best[j - 1];
        --j;
      }
      best[j] = nets[i];
    }
    pthread_mutex_unlock(&net_lock);
    fmt_append(&p, end, "{\"prefix_bits\":%u,\"min_reannounce_interval\":%u,\"tracked_networks\":%u,\"items\":[",
               busy_bits, busy_gap * 60, tracked);
    for (unsigned i = 0; i < n; ++i) {
      uint32_t k = best[i].key;
      fmt_append(&p, end, "%s{\"network\":\"%u.%u.%u.%u/%u\",\"count\":%llu}", i ? "," : "", k >> 24, (k >> 16) & 255,
                 (k >> 8) & 255, k & 255, busy_bits, (unsigned long long)best[i].count);
    }
  } else {
    entry *copy = malloc(limit * sizeof(*copy));
    if (!copy)
      return 0;
    pthread_mutex_lock(&log_lock);
    if (limit > occupied)
      limit = occupied;
    for (unsigned i = 0; i < limit; ++i)
      copy[i] = entries[(next + diag_slots - 1 - i) % diag_slots];
    pthread_mutex_unlock(&log_lock);
    fmt_append(&p, end, "{\"items\":[");
    for (unsigned i = 0; i < limit; ++i) {
      entry *e = copy + i;
      char ip[64];
      ip[ip_format(ip, e->ip)] = 0;
      fmt_append(&p, end, "%s{\"time\":%lld,\"ip\":\"%s\",\"truncated\":%s,\"request\":\"", i ? "," : "",
                 (long long)e->when, ip, e->truncated ? "true" : "false");
      for (unsigned j = 0; j < e->len; ++j) {
        unsigned char c = e->request[j];
        if (c < 32 || c >= 127)
          fmt_append(&p, end, "\\u%04x", c);
        else if (c == '"' || c == '\\')
          fmt_append(&p, end, "\\%c", c);
        else
          fmt_bytes(&p, end, &c, 1);
      }
      fmt_append(&p, end, "\"}");
    }
    free(copy);
  }
  fmt_append(&p, end, "]}\n");
  return p < end ? (size_t)(p - out) : 0;
}

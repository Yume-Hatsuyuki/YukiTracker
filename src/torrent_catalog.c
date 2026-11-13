#include "torrent_catalog.h"
#include "diagnostics.h"
#include "ot_hex.h"
#include "ot_fmt.h"
#include "ot_mutex.h"
#include "ot_scan.h"
#include <arpa/inet.h>
#include <string.h>

typedef struct {
  ot_hash hash;
  size_t seeds, leeches, done;
} row;
typedef struct {
  unsigned key;
  size_t peers;
} network;

int catalog_parse(struct catalog_query *q, const char *text, size_t length) {
  unsigned max = (q->kind == CATALOG_PAGE || q->kind == CATALOG_LOG) ? 1000 : q->kind == CATALOG_TOP ? 100 : 128;
  q->limit = (q->kind == CATALOG_PAGE || q->kind == CATALOG_LOG) ? 100
             : q->kind == CATALOG_BUSY                           ? 20
             : q->kind == CATALOG_TOP                            ? 10
                                                                 : 128;
  unsigned seen = 0;
  while (length) {
    const char *amp = memchr(text, '&', length);
    size_t n = amp ? (size_t)(amp - text) : length;
    unsigned bit;
    if (n > 6 && !memcmp(text, "limit=", 6)) {
      int64_t limit;
      if (scan_int(text + 6, n - 6, &limit) || limit < 1 || limit > max)
        return -1;
      q->limit = (unsigned)limit;
      bit = 1;
    } else if (q->kind == CATALOG_PAGE && n == 47 && !memcmp(text, "cursor=", 7)) {
      if (!hex_to_hash(q->cursor, text + 7))
        return -1;
      q->has_cursor = 1;
      bit = 2;
    } else if (q->kind == CATALOG_TOP && n >= 3 && !memcmp(text, "by=", 3)) {
      if (n == 10 && !memcmp(text + 3, "seeders", 7))
        q->order = 0;
      else if (n == 11 && !memcmp(text + 3, "leechers", 8))
        q->order = 1;
      else if (n == 12 && !memcmp(text + 3, "completed", 9))
        q->order = 2;
      else
        return -1;
      bit = 4;
    } else
      return -1;
    if (seen & bit)
      return -1;
    seen |= bit;
    if (!amp)
      break;
    length -= n + 1;
    text = amp + 1;
    if (!length)
      return -1;
  }
  return 0;
}

static size_t score(row r, unsigned order) { return order == 0 ? r.seeds : order == 1 ? r.leeches : r.done; }
static void hash_text(char dest[41], const ot_hash hash) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < 20; ++i) {
    dest[2 * i] = digits[hash[i] >> 4];
    dest[2 * i + 1] = digits[hash[i] & 15];
  }
  dest[40] = 0;
}

static int count_networks(const ot_vector *v, size_t **blocks) {
  if (OT_VECTOR_HASBUCKETS(v)) {
    const ot_vector *parts = v->data;
    for (size_t i = 0; i < v->size; ++i)
      if (count_networks(parts + i, blocks))
        return -1;
  } else {
    const unsigned char *peer = v->data;
    for (size_t i = 0; i < v->size; ++i, peer += OT_PEER_SIZE4) {
      unsigned prefix = (peer[0] << 8) | peer[1];
      if (!blocks[prefix] && !(blocks[prefix] = calloc(256, sizeof(size_t))))
        return -1;
      ++blocks[prefix][peer[2]];
    }
  }
  return 0;
}

size_t catalog_render(char *out, size_t cap, const struct catalog_query *q) {
  if (q->kind == CATALOG_LOG || q->kind == CATALOG_BUSY)
    return diag_render(out, cap, q->kind == CATALOG_BUSY, q->limit);
  size_t n = 0;
  row *rows = NULL;
  size_t **blocks = NULL;
  network nets[128];
  int more = 0, failed = 0;
  char *p = out, hash[41];
  const char *end = out + cap;
  if (q->kind == CATALOG_NETWORKS)
    blocks = calloc(65536, sizeof(*blocks));
  else
    rows = calloc(q->limit, sizeof(*rows));
  if (!blocks && !rows)
    return 0;

  unsigned first = 0;
  if (q->has_cursor) {
    uint32_t word;
    memcpy(&word, q->cursor, sizeof(word));
    first = ntohl(word) >> OT_BUCKET_COUNT_SHIFT;
  }
  for (unsigned b = first; b < OT_BUCKET_COUNT && !more && !failed; ++b) {
    ot_vector *bucket = mutex_bucket_lock(b);
    ot_torrent *ts = bucket->data;
    size_t start = 0;
    if (q->has_cursor && b == first && bucket->size) {
      int found;
      const ot_torrent *slot = vector_binary_search(q->cursor, ts, bucket->size, sizeof(*ts), sizeof(ot_hash), &found);
      start = (size_t)(slot - ts) + (found != 0);
    }
    for (size_t i = start; i < bucket->size; ++i) {
      ot_torrent *t = ts + i;
      if (blocks) {
        if (t->peer_list && count_networks(&t->peer_list->peers4, blocks)) {
          failed = 1;
          break;
        }
        continue;
      }
      if (q->kind == CATALOG_PAGE && n == q->limit) {
        more = 1;
        break;
      }
      row r;
      memcpy(r.hash, t->hash, 20);
      r.seeds = torrent_seed_count(t);
      r.leeches = torrent_peer_count(t) - r.seeds;
      r.done = t->down_count;
      size_t pos = n;
      if (q->kind == CATALOG_TOP) {
        if (n == q->limit && score(r, q->order) <= score(rows[n - 1], q->order))
          continue;
        if (n == q->limit)
          --pos;
        while (pos && score(rows[pos - 1], q->order) < score(r, q->order)) {
          rows[pos] = rows[pos - 1];
          --pos;
        }
      }
      rows[pos] = r;
      if (n < q->limit)
        ++n;
    }
    mutex_bucket_unlock(b, 0);
  }
  if (blocks) {
    for (unsigned group = 0; group < 65536; ++group) {
      if (!blocks[group])
        continue;
      for (unsigned subnet = 0; subnet < 256; ++subnet) {
        size_t count = blocks[group][subnet];
        if (!count || (n == q->limit && count <= nets[n - 1].peers))
          continue;
        size_t pos = n == q->limit ? n - 1 : n++;
        while (pos && nets[pos - 1].peers < count) {
          nets[pos] = nets[pos - 1];
          --pos;
        }
        nets[pos] = (network){group * 256 + subnet, count};
      }
      free(blocks[group]);
    }
    free(blocks);
  }
  if (failed) {
    free(rows);
    return 0;
  }
  if (q->kind == CATALOG_TOP) {
    const char *names[] = {"seeders", "leechers", "completed"};
    fmt_append(&p, end, "{\"by\":\"%s\",\"items\":[", names[q->order]);
  } else
    fmt_append(&p, end, "{\"items\":[");
  for (size_t i = 0; i < n; ++i) {
    if (i)
      fmt_append(&p, end, ",");
    if (q->kind == CATALOG_NETWORKS) {
      unsigned k = nets[i].key;
      fmt_append(&p, end, "{\"network\":\"%u.%u.%u.0/24\",\"peers\":%zu}", k >> 16, (k >> 8) & 255, k & 255,
                 nets[i].peers);
    } else {
      hash_text(hash, rows[i].hash);
      fmt_append(&p, end, "{\"info_hash\":\"%s\",\"seeders\":%zu,\"leechers\":%zu,\"completed\":%zu}", hash,
                 rows[i].seeds, rows[i].leeches, rows[i].done);
    }
  }
  if (q->kind == CATALOG_PAGE && more)
    fmt_append(&p, end, "],\"next_cursor\":\"%s\"}\n", hash);
  else if (q->kind == CATALOG_PAGE)
    fmt_append(&p, end, "],\"next_cursor\":null}\n");
  else
    fmt_append(&p, end, "]}\n");
  free(rows);
  return p < end ? (size_t)(p - out) : 0;
}

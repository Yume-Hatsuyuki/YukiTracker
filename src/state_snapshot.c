#include "state_snapshot.h"
#include "ot_mutex.h"
#include "ot_hex.h"
#include "ot_scan.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <yaml.h>

static const char *filename;
static unsigned interval;
static pthread_t worker;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static int stopping;

static const char *field(yaml_document_t *doc, yaml_node_t *root, const char *name) {
  for (yaml_node_pair_t *p = root->data.mapping.pairs.start; p < root->data.mapping.pairs.top; ++p) {
    yaml_node_t *k = yaml_document_get_node(doc, p->key), *v = yaml_document_get_node(doc, p->value);
    if (k->type == YAML_SCALAR_NODE && !strcmp((char *)k->data.scalar.value, name) && v->type == YAML_SCALAR_NODE &&
        v->data.scalar.length == strlen((char *)v->data.scalar.value))
      return (char *)v->data.scalar.value;
  }
  return NULL;
}

static int read_record(char *line, int header) {
  yaml_parser_t parser;
  yaml_document_t doc;
  if (!yaml_parser_initialize(&parser))
    return -1;
  yaml_parser_set_input_string(&parser, (unsigned char *)line, strlen(line));
  int ok = yaml_parser_load(&parser, &doc);
  yaml_parser_delete(&parser);
  if (!ok)
    return -1;
  yaml_node_t *obj = yaml_document_get_root_node(&doc);
  ok = 0;
  if (obj && obj->type == YAML_MAPPING_NODE) {
    if (header) {
      const char *f = field(&doc, obj, "format"), *v = field(&doc, obj, "version");
      ok = f && v && !strcmp(f, "yukitracker-state") && !strcmp(v, "1");
    } else {
      const char *h = field(&doc, obj, "info_hash"), *c = field(&doc, obj, "completed");
      ot_hash hash;
      uint64_t count;
      ok = h && c && *c && strlen(h) == 40 && hex_to_hash(hash, h) && scan_uint(c, &count, UINT32_MAX) == strlen(c);
      if (ok && count)
        add_torrent_from_saved_state(hash, 0, count);
    }
  }
  yaml_document_delete(&doc);
  return ok ? 0 : -1;
}

static int save(void) {
  size_t size = strlen(filename) + 16;
  char *tmp = malloc(size);
  if (!tmp)
    return -1;
  snprintf(tmp, size, "%s.tmp.XXXXXX", filename);
  int fd = mkstemp(tmp), ok = 0;
  if (fd < 0) {
    free(tmp);
    return -1;
  }
  FILE *file = fdopen(fd, "w");
  if (file) {
    ok = fputs("{\"format\":\"yukitracker-state\",\"version\":1}\n", file) >= 0;
    for (int b = 0; ok && b < OT_BUCKET_COUNT; ++b) {

      ot_hash after = {0};
      int resume = 0;
      for (;;) {
        struct {
          ot_hash hash;
          uint32_t count;
        } batch[128];
        size_t n = 0;
        ot_vector *v = mutex_bucket_lock(b);
        ot_torrent *rows = v->data;
        size_t lo = 0, hi = v->size;
        while (resume && lo < hi) {
          size_t mid = lo + (hi - lo) / 2;
          if (memcmp(rows[mid].hash, after, 20) <= 0)
            lo = mid + 1;
          else
            hi = mid;
        }
        size_t i = lo;
        for (; i < v->size && n < 128; ++i) {
          if (!rows[i].down_count)
            continue;
          memcpy(batch[n].hash, rows[i].hash, 20);
          batch[n++].count = rows[i].down_count;
        }
        int done = i == v->size;
        mutex_bucket_unlock(b, 0);
        for (size_t j = 0; ok && j < n; ++j) {
          char hash[41];
          hex_from_hash(hash, batch[j].hash);
          ok = fprintf(file, "{\"info_hash\":\"%s\",\"completed\":%u}\n", hash, batch[j].count) > 0;
        }
        if (!ok || done)
          break;
        memcpy(after, batch[n - 1].hash, 20);
        resume = 1;
      }
    }
    if (ok)
      ok = !fflush(file) && !fsync(fd);
    if (fclose(file))
      ok = 0;
  } else
    close(fd);
  if (ok)
    ok = !rename(tmp, filename);
  if (!ok)
    unlink(tmp);
  free(tmp);
  return ok ? 0 : -1;
}

static void *periodic(void *unused) {
  (void)unused;
  pthread_mutex_lock(&lock);
  while (!stopping) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += interval;
    int rc = 0;
    while (!stopping && !rc)
      rc = pthread_cond_timedwait(&wake, &lock, &ts);
    if (stopping)
      break;
    pthread_mutex_unlock(&lock);
    if (save())
      perror("state snapshot");
    pthread_mutex_lock(&lock);
  }
  pthread_mutex_unlock(&lock);
  return NULL;
}

void state_snapshot_start(const char *path, unsigned period) {
  if (!path)
    return;
  filename = path;
  interval = period;
  FILE *file = fopen(path, "r");
  if (!file && errno != ENOENT)
    exerr("Cannot open state file");
  if (file) {
    char line[1024];
    size_t lineno = 0;
    while (fgets(line, sizeof(line), file)) {
      ++lineno;
      if ((!strchr(line, '\n') && !feof(file)) || read_record(line, lineno == 1)) {
        fprintf(stderr, "Invalid snapshot %s line %zu\n", path, lineno);
        exit(1);
      }
    }
    if (!lineno || ferror(file))
      exerr("Invalid or unreadable snapshot");
    fclose(file);
  }
  if (period && pthread_create(&worker, NULL, periodic, NULL))
    exerr("Cannot start snapshot worker");
}

int state_snapshot_stop(void) {
  if (!filename)
    return 0;
  if (interval) {
    pthread_mutex_lock(&lock);
    stopping = 1;
    pthread_cond_signal(&wake);
    pthread_mutex_unlock(&lock);
    pthread_join(worker, NULL);
  }
  return save();
}

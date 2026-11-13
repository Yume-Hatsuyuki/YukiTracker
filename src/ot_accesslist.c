/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(WANT_ACCESSLIST_BLACK) || defined(WANT_ACCESSLIST_WHITE)
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif
#ifdef WANT_DYNAMIC_ACCESSLIST
#include <errno.h>
#endif

#include "ot_accesslist.h"
#include "ot_hex.h"
#include "ot_ip.h"
#include "ot_vector.h"
#include "trackerlogic.h"

#ifdef WANT_ACCESSLIST
const char *g_accesslist_filename = NULL;
int g_whitelist;
#ifdef WANT_DYNAMIC_ACCESSLIST
const char *g_accesslist_pipe_add = NULL;
const char *g_accesslist_pipe_delete = NULL;
#endif
static pthread_mutex_t g_accesslist_mutex = PTHREAD_MUTEX_INITIALIZER;

struct ot_accesslist;
typedef struct ot_accesslist ot_accesslist;
struct ot_accesslist {
  ot_hash *list;
  size_t size;
  ot_time base;
  ot_accesslist *next;
};
static ot_accesslist *_Atomic g_accesslist = NULL;
#ifdef WANT_DYNAMIC_ACCESSLIST
static ot_accesslist *_Atomic g_accesslist_add = NULL;
static ot_accesslist *_Atomic g_accesslist_delete = NULL;
#endif

static int vector_compare_hash(const void *hash1, const void *hash2) {
  return memcmp(hash1, hash2, OT_HASH_COMPARE_SIZE);
}

static ot_accesslist *accesslist_free(ot_accesslist *accesslist) {
  while (accesslist) {
    ot_accesslist *this_accesslist = accesslist;
    accesslist = this_accesslist->next;
    free(this_accesslist->list);
    free(this_accesslist);
  }
  return NULL;
}

static ot_accesslist *accesslist_make(ot_accesslist *next, size_t size) {
  ot_accesslist *accesslist_new = malloc(sizeof(ot_accesslist));
  if (accesslist_new) {
    accesslist_new->list = size ? malloc(sizeof(ot_hash) * size) : NULL;
    accesslist_new->size = size;
    accesslist_new->base = 0;
    accesslist_new->next = next;
    if (size && !accesslist_new->list) {
      free(accesslist_new);
      accesslist_new = NULL;
    }
  }
  return accesslist_new;
}

/* This must be called with g_accesslist_mutex held.
   This will never delete head, because that might still be in use. */
static void accesslist_clean(ot_accesslist *accesslist) {
  while (accesslist && accesslist->next) {
    if (time_since_minutes(accesslist->next->base) > 5)
      accesslist->next = accesslist_free(accesslist->next);
    accesslist = accesslist->next;
  }
}

size_t accesslist_parse_hashes(ot_hash *dest, size_t capacity, const char *buf, size_t len) {
  const char *end = buf + len;
  const char *offs = buf;
  size_t count = 0;

  while (count < capacity && end - offs >= 40) {
    if (hex_to_hash(dest[count], offs)) {
      offs += 40;

      if (offs == end || !hex_isdigit((unsigned char)*offs))
        ++count;
    }

    while (offs < end && *(offs++) != '\n') {
    }
  }

  return count;
}

static int accesslist_map(const char *filename, const char **map, size_t *maplen) {
  struct stat st;
  void *mapped;
  int fd = open(filename, O_RDONLY);

  if (fd < 0)
    return -1;

  if (fstat(fd, &st) < 0 || st.st_size < 0 || (uintmax_t)st.st_size > (uintmax_t)SIZE_MAX) {
    close(fd);
    return -1;
  }

  if (st.st_size == 0) {
    close(fd);
    *map = NULL;
    *maplen = 0;
    return 0;
  }

  mapped = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  close(fd);

  if (mapped == MAP_FAILED)
    return -1;

  *map = mapped;
  *maplen = (size_t)st.st_size;
  return 0;
}

static void accesslist_readfile(void) {
  ot_accesslist *accesslist_new;
  const char *map;
  size_t maplen, capacity, found;

  if (!g_accesslist_filename)
    return;

  if (accesslist_map(g_accesslist_filename, &map, &maplen) < 0) {
    char *wd = getcwd(NULL, 0);
    fprintf(stderr,
            "Warning: Can't open accesslist file: %s (but will try to create it later, if necessary and "
            "possible).\nPWD: %s\n",
            g_accesslist_filename, wd);
    free(wd);
    return;
  }

  capacity = (maplen + 1) / 41;
  accesslist_new = accesslist_make(g_accesslist, capacity);
  if (!accesslist_new) {
    fprintf(stderr, "Warning: Not enough memory to allocate %zd bytes for accesslist buffer. May succeed later.\n",
            capacity * sizeof(ot_hash));
    if (map)
      munmap((void *)map, maplen);
    return;
  }

  found = maplen ? accesslist_parse_hashes(accesslist_new->list, capacity, map, maplen) : 0;

  if (map)
    munmap((void *)map, maplen);

  if (found)
    qsort(accesslist_new->list, found, sizeof(ot_hash), vector_compare_hash);
  accesslist_new->size = found;

  pthread_mutex_lock(&g_accesslist_mutex);

  if (g_accesslist)
    g_accesslist->base = time_now_minutes();
  accesslist_new->next = g_accesslist;
  g_accesslist = accesslist_new;

#ifdef WANT_DYNAMIC_ACCESSLIST

  if (g_accesslist_add && (accesslist_new = accesslist_make(g_accesslist_add, 0)) != NULL) {
    g_accesslist_add->base = time_now_minutes();
    g_accesslist_add = accesslist_new;
  }
  if (g_accesslist_delete && (accesslist_new = accesslist_make(g_accesslist_delete, 0)) != NULL) {
    g_accesslist_delete->base = time_now_minutes();
    g_accesslist_delete = accesslist_new;
  }
#endif

  accesslist_clean(g_accesslist);

  pthread_mutex_unlock(&g_accesslist_mutex);
}

int accesslist_hashisvalid(const ot_hash hash) {

  ot_accesslist *accesslist = g_accesslist;
#ifdef WANT_DYNAMIC_ACCESSLIST
  ot_accesslist *accesslist_add, *accesslist_delete;
#endif
  void *exactmatch = NULL;

  if (accesslist && accesslist->size)
    exactmatch = bsearch(hash, accesslist->list, accesslist->size, OT_HASH_COMPARE_SIZE, vector_compare_hash);

#ifdef WANT_DYNAMIC_ACCESSLIST

  accesslist_add = g_accesslist_add;
  if ((exactmatch == NULL) && accesslist_add && accesslist_add->size)
    exactmatch = bsearch(hash, accesslist_add->list, accesslist_add->size, OT_HASH_COMPARE_SIZE, vector_compare_hash);

  accesslist_delete = g_accesslist_delete;
  if ((exactmatch != NULL) && accesslist_delete && accesslist_delete->size &&
      bsearch(hash, accesslist_delete->list, accesslist_delete->size, OT_HASH_COMPARE_SIZE, vector_compare_hash))
    exactmatch = NULL;
#endif

#ifdef WANT_ACCESSLIST_BLACK
  return g_whitelist ? exactmatch != NULL : exactmatch == NULL;
#else
  return exactmatch != NULL;
#endif
}

static void *accesslist_worker(void *args) {
  int sig;
  sigset_t signal_mask;

  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGHUP);

  (void)args;

  while (1) {

    while (sigwait(&signal_mask, &sig) != 0)
      ;

    if (!tracker_running)
      return NULL;

    accesslist_readfile();
  }
  return NULL;
}

#ifdef WANT_DYNAMIC_ACCESSLIST
static pthread_t thread_adder_id, thread_deleter_id;
static _Atomic int adder_left, deleter_left;
static void *accesslist_adddel_worker(const char *fifoname, ot_accesslist *_Atomic *adding_to,
                                      ot_accesslist *_Atomic *removing_from) {
  struct stat st;

  if (!stat(fifoname, &st)) {
    if (!S_ISFIFO(st.st_mode)) {
      fprintf(stderr,
              "Error when starting dynamic accesslists: Found Non-FIFO file at %s.\nPlease remove it and restart "
              "YukiTracker.\n",
              fifoname);
      return NULL;
    }
  } else {
    int error = mkfifo(fifoname, 0755);
    if (error && error != EEXIST) {
      fprintf(stderr, "Error when starting dynamic accesslists: Couldn't create FIFO at %s, error: %s\n", fifoname,
              strerror(errno));
      return NULL;
    }
  }

  while (tracker_running) {
    FILE *fifo = fopen(fifoname, "r");
    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;

    if (!fifo) {

      if (errno == EINTR)
        continue;
      fprintf(stderr, "Error when reading dynamic accesslists: Couldn't open FIFO at %s, error: %s\n", fifoname,
              strerror(errno));
      return NULL;
    }

    while ((linelen = getline(&line, &linecap, fifo)) > 0) {
      ot_hash info_hash;

      printf("Got line %*s", (int)linelen, line);

      if (linelen < 41)
        continue;

      if (!hex_to_hash(info_hash, line))
        continue;

      pthread_mutex_lock(&g_accesslist_mutex);

      if (*removing_from && (*removing_from)->list) {
        ot_hash *exactmatch = bsearch(info_hash, (*removing_from)->list, (*removing_from)->size, OT_HASH_COMPARE_SIZE,
                                      vector_compare_hash);
        if (exactmatch) {
          ptrdiff_t off = exactmatch - (*removing_from)->list;
          ot_accesslist *accesslist_new = accesslist_make(*removing_from, (*removing_from)->size - 1);
          if (accesslist_new) {
            size_t after = (*removing_from)->size - off - 1;

            if (off)
              memcpy(accesslist_new->list, (*removing_from)->list, sizeof(ot_hash) * off);
            if (after)
              memcpy(accesslist_new->list + off, (*removing_from)->list + off + 1, sizeof(ot_hash) * after);
            (*removing_from)->base = time_now_minutes();
            *removing_from = accesslist_new;
          }
        }
      }

      if (!*adding_to) {
        ot_accesslist *accesslist_new = accesslist_make(NULL, 1);
        if (accesslist_new) {
          memcpy(accesslist_new->list, info_hash, sizeof(ot_hash));
          *adding_to = accesslist_new;
        }
      } else {
        int exactmatch = 0;
        ot_hash *insert_point = vector_binary_search(info_hash, (*adding_to)->list, (*adding_to)->size, sizeof(ot_hash),
                                                     OT_HASH_COMPARE_SIZE, &exactmatch);

        if (!exactmatch) {
          ot_accesslist *accesslist_new = accesslist_make(*adding_to, (*adding_to)->size + 1);
          if (accesslist_new) {
            ptrdiff_t off = (*adding_to)->size ? insert_point - (*adding_to)->list : 0;
            size_t after = (*adding_to)->size - off;

            if (off)
              memcpy(accesslist_new->list, (*adding_to)->list, sizeof(ot_hash) * off);
            memcpy(accesslist_new->list + off, info_hash, sizeof(info_hash));
            if (after)
              memcpy(accesslist_new->list + off + 1, (*adding_to)->list + off, sizeof(ot_hash) * after);
            (*adding_to)->base = time_now_minutes();
            *adding_to = accesslist_new;
          }
        }
      }

      pthread_mutex_unlock(&g_accesslist_mutex);
    }

    free(line);
    fclose(fifo);
  }
  return NULL;
}

static void *accesslist_adder_worker(void *args) {
  (void)args;
  accesslist_adddel_worker(g_accesslist_pipe_add, &g_accesslist_add, &g_accesslist_delete);
  atomic_store(&adder_left, 1);
  return NULL;
}
static void *accesslist_deleter_worker(void *args) {
  (void)args;
  accesslist_adddel_worker(g_accesslist_pipe_delete, &g_accesslist_delete, &g_accesslist_add);
  atomic_store(&deleter_left, 1);
  return NULL;
}

static void accesslist_stop_fifo_worker(pthread_t thread, _Atomic int *left, const char *pipe_name) {
  if (!pipe_name)
    return;

  while (!atomic_load(left)) {
    pthread_kill(thread, OT_SIGNAL_WAKE);
    usleep(1000);
  }
  pthread_join(thread, NULL);
}
#endif

static pthread_t thread_id;
void accesslist_init(void) {

  accesslist_readfile();
  if (g_accesslist_filename && !g_accesslist)
    exerr("Cannot load initial access list");

  if (pthread_create(&thread_id, NULL, accesslist_worker, NULL))
    exerr("Cannot create accesslist worker thread.");
#ifdef WANT_DYNAMIC_ACCESSLIST
  if (g_accesslist_pipe_add && pthread_create(&thread_adder_id, NULL, accesslist_adder_worker, NULL))
    exerr("Cannot create accesslist adder thread.");
  if (g_accesslist_pipe_delete && pthread_create(&thread_deleter_id, NULL, accesslist_deleter_worker, NULL))
    exerr("Cannot create accesslist deleter thread.");
#endif
}

void accesslist_deinit(void) {

  pthread_kill(thread_id, SIGHUP);
  pthread_join(thread_id, NULL);

#ifdef WANT_DYNAMIC_ACCESSLIST

  accesslist_stop_fifo_worker(thread_adder_id, &adder_left, g_accesslist_pipe_add);
  accesslist_stop_fifo_worker(thread_deleter_id, &deleter_left, g_accesslist_pipe_delete);
#endif

  pthread_mutex_lock(&g_accesslist_mutex);

  g_accesslist = accesslist_free(g_accesslist);

#ifdef WANT_DYNAMIC_ACCESSLIST
  g_accesslist_add = accesslist_free(g_accesslist_add);
  g_accesslist_delete = accesslist_free(g_accesslist_delete);
#endif

  pthread_mutex_unlock(&g_accesslist_mutex);
}

void accesslist_cleanup(void) {
  pthread_mutex_lock(&g_accesslist_mutex);

  accesslist_clean(g_accesslist);
#if WANT_DYNAMIC_ACCESSLIST
  accesslist_clean(g_accesslist_add);
  accesslist_clean(g_accesslist_delete);
#endif

  pthread_mutex_unlock(&g_accesslist_mutex);
}
#endif

int accesslist_address_in_net(const ot_ip6 address, const ot_net *net) {
  int bits = net->bits, checkbits = (0x7f00 >> (bits & 7));
  int result = memcmp(address, &net->address, bits >> 3);
  if (!result && (bits & 7))
    result = (checkbits & address[bits >> 3]) - (checkbits & net->address[bits >> 3]);
  return result == 0;
}

void *accesslist_set_value_for_net(const ot_net *net, ot_vector *vector, const void *value, const size_t member_size) {
  size_t i;
  int exactmatch;

  if (member_size < sizeof(ot_net))
    return 0;

  uint8_t *member = ((uint8_t *)vector->data);
  for (i = 0; i < vector->size; ++i) {
    if (accesslist_address_in_net(*(ot_ip6 *)member, net) || accesslist_address_in_net(net->address, (ot_net *)member))
      return 0;
    member += member_size;
  }

  member = vector_find_or_insert(vector, (void *)net, member_size, sizeof(ot_net), &exactmatch);
  if (member) {
    memcpy(member, net, sizeof(ot_net));
    memcpy(member + sizeof(ot_net), value, member_size - sizeof(ot_net));
  }

  return member;
}

void *accesslist_get_value_for_net(const ot_ip6 address, const ot_vector *vector, const size_t member_size) {
  int exactmatch;

  ot_net *net = vector_binary_search(address, vector->data, vector->size, member_size, sizeof(ot_ip6), &exactmatch);
  if (!net)
    return NULL;

  if (!exactmatch && ((void *)net > vector->data))
    --net;
  if (!accesslist_address_in_net(address, net))
    return NULL;
  return (void *)net;
}

#ifdef WANT_IP_FROM_PROXY
typedef struct {
  ot_net *proxy;
  ot_vector networks;
} ot_proxymap;

static ot_vector g_proxies_list;
static pthread_mutex_t g_proxies_list_mutex = PTHREAD_MUTEX_INITIALIZER;

int proxylist_add_network(const ot_net *proxy, const ot_net *net) {
  ot_proxymap *map;
  int exactmatch, result = 1;
  pthread_mutex_lock(&g_proxies_list_mutex);

  map = vector_binary_search(proxy, g_proxies_list.data, g_proxies_list.size, sizeof(ot_proxymap), sizeof(ot_net),
                             &exactmatch);

  if (!map || !exactmatch) {

    ot_vector empty;
    memset(&empty, 0, sizeof(ot_vector));
    map = accesslist_set_value_for_net(proxy, &g_proxies_list, &empty, sizeof(ot_proxymap));
  }

  if (map && accesslist_set_value_for_net(net, &map->networks, NULL, sizeof(ot_net)))
    result = 1;

  pthread_mutex_unlock(&g_proxies_list_mutex);
  return result;
}

int proxylist_check_proxy(const ot_ip6 proxy, const ot_ip6 address) {
  int result = 0;
  ot_proxymap *map;

  pthread_mutex_lock(&g_proxies_list_mutex);

  if ((map = accesslist_get_value_for_net(proxy, &g_proxies_list, sizeof(ot_proxymap))))
    if (!address || accesslist_get_value_for_net(address, &map->networks, sizeof(ot_net)))
      result = 1;

  pthread_mutex_unlock(&g_proxies_list_mutex);
  return result;
}

#endif

static ot_net g_admin_nets[OT_ADMINIP_MAX];
static ot_permissions g_admin_nets_permissions[OT_ADMINIP_MAX];
static size_t g_admin_nets_count = 0;

int accesslist_bless_net(ot_net *net, ot_permissions permissions) {
  if (g_admin_nets_count >= OT_ADMINIP_MAX)
    return -1;

  memcpy(g_admin_nets + g_admin_nets_count, net, sizeof(ot_net));
  g_admin_nets_permissions[g_admin_nets_count++] = permissions;

  return 0;
}

int accesslist_is_blessed(const ot_ip6 ip, ot_permissions permissions) {
  size_t i;
  for (i = 0; i < g_admin_nets_count; ++i)
    if (accesslist_address_in_net(ip, g_admin_nets + i) && (g_admin_nets_permissions[i] & permissions))
      return 1;
  return 0;
}

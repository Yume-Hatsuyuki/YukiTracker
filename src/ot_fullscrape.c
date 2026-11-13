/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#ifdef WANT_FULLSCRAPE

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#ifdef WANT_COMPRESSION_GZIP
#include <zlib.h>
#endif
#ifdef WANT_COMPRESSION_ZSTD
#include <zstd.h>
#endif

#include "ot_fmt.h"
#include "ot_hex.h"
#include "ot_fullscrape.h"
#include "ot_iovec.h"
#include "ot_mutex.h"
#include "ot_workqueue.h"
#include "ot_urlencoded.h"
#include "trackerlogic.h"

#define OT_SCRAPE_CHUNK_SIZE (1024 * 1024)

#define OT_SCRAPE_MAXENTRYLEN 256

static void fullscrape_make(int taskid, ot_tasktype mode);
#ifdef WANT_COMPRESSION_GZIP
static void fullscrape_make_gzip(int taskid, ot_tasktype mode);
#endif
#ifdef WANT_COMPRESSION_ZSTD
static void fullscrape_make_zstd(int taskid, ot_tasktype mode);
#endif

static void *fullscrape_worker(void *args) {
  (void)args;

  while (tracker_running) {
    ot_tasktype tasktype = TASK_FULLSCRAPE;
    ot_taskid taskid = workqueue_poptask(&tasktype);
    if (!taskid)
      break;
#ifdef WANT_COMPRESSION_ZSTD
    if (tasktype & TASK_FLAG_ZSTD)
      fullscrape_make_zstd(taskid, tasktype);
    else
#endif
#ifdef WANT_COMPRESSION_GZIP
        if (tasktype & TASK_FLAG_GZIP)
      fullscrape_make_gzip(taskid, tasktype);
    else
#endif
      fullscrape_make(taskid, tasktype);
    workqueue_pushchunked(taskid, NULL);
  }
  return NULL;
}

static pthread_t thread_id;
void fullscrape_init(void) {
  if (pthread_create(&thread_id, NULL, fullscrape_worker, NULL))
    exerr("Cannot create fullscrape worker thread.");
}

void fullscrape_deinit(void) {
  workqueue_wakeall();
  pthread_join(thread_id, NULL);
}

void fullscrape_deliver(int64_t sock, ot_tasktype tasktype) { workqueue_pushtask(sock, TASK_FULLSCRAPE | tasktype); }

static void fullscrape_write_one(ot_tasktype mode, char **cursor, ot_torrent *torrent, ot_hash *hash) {

  char *r = *cursor;
  const char *r_end = r + OT_SCRAPE_MAXENTRYLEN;
  size_t seed_count = torrent_seed_count(torrent);
  size_t peer_count = torrent_peer_count(torrent);
  size_t down_count = torrent->down_count;

  switch (mode & TASK_TASK_MASK) {
  case TASK_FULLSCRAPE:
  default:

    *r++ = '2';
    *r++ = '0';
    *r++ = ':';
    memcpy(r, hash, sizeof(ot_hash));
    r += sizeof(ot_hash);

    fmt_append(&r, r_end, "d8:completei%zde10:downloadedi%zde10:incompletei%zdee", seed_count, down_count,
               peer_count - seed_count);

    break;
  case TASK_FULLSCRAPE_NDJSON: {
    static const char digits[] = "0123456789abcdef";
    fmt_append(&r, r_end, "{\"info_hash\":\"");
    for (size_t i = 0; i < sizeof(ot_hash); ++i) {
      *r++ = digits[(*hash)[i] >> 4];
      *r++ = digits[(*hash)[i] & 15];
    }
    fmt_append(&r, r_end, "\",\"seeders\":%zu,\"leechers\":%zu,\"completed\":%zu}\n", seed_count,
               peer_count - seed_count, down_count);
    break;
  }
  case TASK_FULLSCRAPE_TPB_ASCII:
    hex_from_hash(r, *hash);
    r += 2 * sizeof(ot_hash);
    fmt_append(&r, r_end, ":%zd:%zd\n", seed_count, peer_count - seed_count);
    break;
  case TASK_FULLSCRAPE_TPB_ASCII_PLUS:
    hex_from_hash(r, *hash);
    r += 2 * sizeof(ot_hash);
    fmt_append(&r, r_end, ":%zd:%zd:%zd\n", seed_count, peer_count - seed_count, down_count);
    break;
  case TASK_FULLSCRAPE_TPB_BINARY:
    memcpy(r, *hash, sizeof(ot_hash));
    r += sizeof(ot_hash);
    *(uint32_t *)(r + 0) = htonl((uint32_t)seed_count);
    *(uint32_t *)(r + 4) = htonl((uint32_t)(peer_count - seed_count));
    r += 8;
    break;
  case TASK_FULLSCRAPE_TPB_URLENCODED:
    r += urlencoded_format(r, *hash, sizeof(ot_hash));
    fmt_append(&r, r_end, ":%zd:%zd\n", seed_count, peer_count - seed_count);
    break;
  case TASK_FULLSCRAPE_TRACKERSTATE:
    hex_from_hash(r, *hash);
    r += 2 * sizeof(ot_hash);
    fmt_append(&r, r_end, ":%zd:%zd\n", (ssize_t)(time_wall_minutes() - time_since_minutes(torrent->base)), down_count);
    break;
  }
  *cursor = r;
}

static void fullscrape_make(int taskid, ot_tasktype mode) {
  size_t bucket;
  char *r, *re;
  struct iovec iovector = {NULL, 0};

  r = iovector.iov_base = malloc(OT_SCRAPE_CHUNK_SIZE);
  if (!r)
    return;

  re = r + OT_SCRAPE_CHUNK_SIZE - OT_SCRAPE_MAXENTRYLEN;

  if ((mode & TASK_TASK_MASK) == TASK_FULLSCRAPE)
    fmt_append(&r, (char *)iovector.iov_base + OT_SCRAPE_CHUNK_SIZE, "d5:filesd");

  for (bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket) {

    ot_vector *torrents_list = mutex_bucket_lock(bucket);
    ot_torrent *torrents = (ot_torrent *)(torrents_list->data);
    size_t i;

    for (i = 0; i < torrents_list->size; ++i) {
      fullscrape_write_one(mode, &r, torrents + i, &torrents[i].hash);

      if (r > re) {
        iovector.iov_len = r - (char *)iovector.iov_base;

        if (workqueue_pushchunked(taskid, &iovector)) {
          free(iovector.iov_base);
          mutex_bucket_unlock(bucket, 0);
          return;
        }

        r = iovector.iov_base = malloc(OT_SCRAPE_CHUNK_SIZE);
        if (!r) {
          mutex_bucket_unlock(bucket, 0);
          return;
        }

        re = r + OT_SCRAPE_CHUNK_SIZE - OT_SCRAPE_MAXENTRYLEN;
      }
    }

    mutex_bucket_unlock(bucket, 0);

    if (!tracker_running) {
      free(iovector.iov_base);
      return;
    }
  }

  if ((mode & TASK_TASK_MASK) == TASK_FULLSCRAPE)
    fmt_append(&r, (char *)iovector.iov_base + OT_SCRAPE_CHUNK_SIZE, "ee");

  iovector.iov_len = r - (char *)iovector.iov_base;
  if (workqueue_pushchunked(taskid, &iovector))
    free(iovector.iov_base);
}

#ifdef WANT_COMPRESSION_GZIP

static void fullscrape_make_gzip(int taskid, ot_tasktype mode) {
  size_t bucket;
  char *r;
  struct iovec iovector = {NULL, 0};
  int zres;
  z_stream strm;

  iovector.iov_base = malloc(OT_SCRAPE_CHUNK_SIZE);
  if (!iovector.iov_base)
    return;

  memset(&strm, 0, sizeof(strm));
  strm.next_out = (uint8_t *)iovector.iov_base;
  strm.avail_out = OT_SCRAPE_CHUNK_SIZE;
  if (deflateInit2(&strm, 7, Z_DEFLATED, 31, 9, Z_DEFAULT_STRATEGY) != Z_OK) {
    free(iovector.iov_base);
    return;
  }

  if ((mode & TASK_TASK_MASK) == TASK_FULLSCRAPE) {
    strm.next_in = (uint8_t *)"d5:filesd";
    strm.avail_in = strlen("d5:filesd");
    zres = deflate(&strm, Z_NO_FLUSH);
  }

  for (bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket) {

    ot_vector *torrents_list = mutex_bucket_lock(bucket);
    ot_torrent *torrents = (ot_torrent *)(torrents_list->data);
    size_t i;

    for (i = 0; i < torrents_list->size; ++i) {
      char compress_buffer[OT_SCRAPE_MAXENTRYLEN];
      r = compress_buffer;
      fullscrape_write_one(mode, &r, torrents + i, &torrents[i].hash);
      strm.next_in = (uint8_t *)compress_buffer;
      strm.avail_in = r - compress_buffer;
      zres = deflate(&strm, Z_NO_FLUSH);
      if ((zres < Z_OK) && (zres != Z_BUF_ERROR))
        fprintf(stderr, "deflate() failed while in fullscrape_make().\n");

      while (!strm.avail_out) {
        iovector.iov_len = (char *)strm.next_out - (char *)iovector.iov_base;

        if (workqueue_pushchunked(taskid, &iovector)) {
          free(iovector.iov_base);
          deflateEnd(&strm);
          mutex_bucket_unlock(bucket, 0);
          return;
        }

        iovector.iov_base = malloc(OT_SCRAPE_CHUNK_SIZE);
        if (!iovector.iov_base) {
          fprintf(stderr, "Out of memory trying to claim ouput buffer\n");
          deflateEnd(&strm);
          mutex_bucket_unlock(bucket, 0);
          return;
        }
        strm.next_out = (uint8_t *)iovector.iov_base;
        strm.avail_out = OT_SCRAPE_CHUNK_SIZE;
        zres = deflate(&strm, Z_NO_FLUSH);
        if ((zres < Z_OK) && (zres != Z_BUF_ERROR))
          fprintf(stderr, "deflate() failed while in fullscrape_make().\n");
      }
    }

    mutex_bucket_unlock(bucket, 0);

    if (!tracker_running) {
      free(iovector.iov_base);
      deflateEnd(&strm);
      return;
    }
  }

  if ((mode & TASK_TASK_MASK) == TASK_FULLSCRAPE) {
    strm.next_in = (uint8_t *)"ee";
    strm.avail_in = strlen("ee");
  }

  if (deflate(&strm, Z_FINISH) < Z_OK)
    fprintf(stderr, "deflate() failed while in fullscrape_make()'s endgame.\n");

  iovector.iov_len = (char *)strm.next_out - (char *)iovector.iov_base;
  if (workqueue_pushchunked(taskid, &iovector)) {
    free(iovector.iov_base);
    deflateEnd(&strm);
    return;
  }

  if (!strm.avail_out) {

    iovector.iov_base = malloc(OT_SCRAPE_CHUNK_SIZE);

    if (!iovector.iov_base) {
      fprintf(stderr, "Problem with iovec_next_chunk\n");
      deflateEnd(&strm);
      return;
    }
    strm.next_out = iovector.iov_base;
    strm.avail_out = OT_SCRAPE_CHUNK_SIZE;
    if (deflate(&strm, Z_FINISH) < Z_OK)
      fprintf(stderr, "deflate() failed while in fullscrape_make()'s endgame.\n");

    iovector.iov_len = (char *)strm.next_out - (char *)iovector.iov_base;
    if (!iovector.iov_len || workqueue_pushchunked(taskid, &iovector))
      free(iovector.iov_base);
  }

  deflateEnd(&strm);
}

#endif

#ifdef WANT_COMPRESSION_ZSTD

static void fullscrape_make_zstd(int taskid, ot_tasktype mode) {
  int bucket;
  char *r;
  struct iovec iovector = {NULL, 0};
  ZSTD_CCtx *zstream = ZSTD_createCCtx();
  ZSTD_inBuffer inbuf;
  ZSTD_outBuffer outbuf;
  size_t more_bytes;

  if (!zstream)
    return;

  iovector.iov_base = malloc(OT_SCRAPE_CHUNK_SIZE);
  if (!iovector.iov_base) {
    ZSTD_freeCCtx(zstream);
    return;
  }

  ZSTD_CCtx_setParameter(zstream, ZSTD_c_compressionLevel, 6);

  outbuf.dst = iovector.iov_base;
  outbuf.size = OT_SCRAPE_CHUNK_SIZE;
  outbuf.pos = 0;

  if ((mode & TASK_TASK_MASK) == TASK_FULLSCRAPE) {
    inbuf.src = (const void *)"d5:filesd";
    inbuf.size = strlen("d5:filesd");
    inbuf.pos = 0;
    ZSTD_compressStream2(zstream, &outbuf, &inbuf, ZSTD_e_continue);
  }

  for (bucket = 0; bucket < OT_BUCKET_COUNT; ++bucket) {

    ot_vector *torrents_list = mutex_bucket_lock(bucket);
    ot_torrent *torrents = (ot_torrent *)(torrents_list->data);
    size_t i;

    for (i = 0; i < torrents_list->size; ++i) {
      char compress_buffer[OT_SCRAPE_MAXENTRYLEN];
      r = compress_buffer;
      fullscrape_write_one(mode, &r, torrents + i, &torrents[i].hash);
      inbuf.src = compress_buffer;
      inbuf.size = r - compress_buffer;
      inbuf.pos = 0;
      ZSTD_compressStream2(zstream, &outbuf, &inbuf, ZSTD_e_continue);

      while (outbuf.pos + OT_SCRAPE_MAXENTRYLEN > outbuf.size) {
        iovector.iov_len = outbuf.size;

        if (workqueue_pushchunked(taskid, &iovector)) {
          free(iovector.iov_base);
          ZSTD_freeCCtx(zstream);
          return mutex_bucket_unlock(bucket, 0);
        }

        iovector.iov_base = malloc(OT_SCRAPE_CHUNK_SIZE);
        if (!iovector.iov_base) {
          fprintf(stderr, "Out of memory trying to claim ouput buffer\n");
          ZSTD_freeCCtx(zstream);
          return mutex_bucket_unlock(bucket, 0);
        }

        outbuf.dst = iovector.iov_base;
        outbuf.size = OT_SCRAPE_CHUNK_SIZE;
        outbuf.pos = 0;

        ZSTD_compressStream2(zstream, &outbuf, &inbuf, ZSTD_e_continue);
      }
    }

    mutex_bucket_unlock(bucket, 0);

    if (!tracker_running) {
      free(iovector.iov_base);
      ZSTD_freeCCtx(zstream);
      return;
    }
  }

  if ((mode & TASK_TASK_MASK) == TASK_FULLSCRAPE) {
    inbuf.src = (const void *)"ee";
    inbuf.size = strlen("ee");
    inbuf.pos = 0;
  }

  more_bytes = ZSTD_compressStream2(zstream, &outbuf, &inbuf, ZSTD_e_end);

  iovector.iov_len = outbuf.pos;
  if (workqueue_pushchunked(taskid, &iovector)) {
    free(iovector.iov_base);
    ZSTD_freeCCtx(zstream);
    return;
  }

  if (more_bytes) {

    iovector.iov_base = malloc(OT_SCRAPE_CHUNK_SIZE);

    if (!iovector.iov_base) {
      fprintf(stderr, "Problem with iovec_next_chunk\n");
      ZSTD_freeCCtx(zstream);
      return;
    }

    outbuf.dst = iovector.iov_base;
    outbuf.size = OT_SCRAPE_CHUNK_SIZE;
    outbuf.pos = 0;

    ZSTD_compressStream2(zstream, &outbuf, &inbuf, ZSTD_e_end);

    iovector.iov_len = outbuf.pos;
    if (!iovector.iov_len || workqueue_pushchunked(taskid, &iovector))
      free(iovector.iov_base);
  }

  ZSTD_freeCCtx(zstream);
}

#endif

#endif

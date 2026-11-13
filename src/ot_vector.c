/* This software was written by Dirk Engling <erdgeist@erdgeist.org>
   It is considered beerware. Prost. Skol. Cheers or whatever. */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "trackerlogic.h"

static int vector_compare_peer6(const void *peer1, const void *peer2) {
  return memcmp(peer1, peer2, OT_PEER_COMPARE_SIZE6);
}
static int vector_compare_peer4(const void *peer1, const void *peer2) {
  return memcmp(peer1, peer2, OT_PEER_COMPARE_SIZE4);
}

void *vector_binary_search(const void *const key, const void *base, const size_t member_count, const size_t member_size,
                           size_t compare_size, int *exactmatch) {
  size_t interval = member_count;

  while (interval) {
    uint8_t *lookat = ((uint8_t *)base) + member_size * (interval / 2);
    int cmp = memcmp(lookat, key, compare_size);
    if (cmp == 0) {
      base = lookat;
      break;
    }
    if (cmp < 0) {
      base = lookat + member_size;
      interval--;
    }
    interval /= 2;
  }

  *exactmatch = interval;
  return (void *)base;
}

static uint8_t vector_hash_peer(ot_peer const *peer, size_t compare_size, size_t bucket_count) {
  unsigned int hash = 5381;
  uint8_t *p = (uint8_t *)peer;
  while (compare_size--)
    hash += (hash << 5) + *(p++);
  return hash % bucket_count;
}

void *vector_find_or_insert(ot_vector *vector, void *key, size_t member_size, size_t compare_size, int *exactmatch) {
  uint8_t *match = vector_binary_search(key, vector->data, vector->size, member_size, compare_size, exactmatch);
  size_t match_offset, bytes_after;

  if (*exactmatch)
    return match;

  match_offset = vector->size ? (size_t)(match - (uint8_t *)vector->data) : 0;
  bytes_after = member_size * vector->size - match_offset;

  if (vector->size + 1 > vector->space) {
    size_t new_space = vector->space ? OT_VECTOR_GROW_RATIO * vector->space : OT_VECTOR_MIN_MEMBERS;
    uint8_t *new_data = realloc(vector->data, new_space * member_size);

    if (!new_data)
      return NULL;

    vector->data = new_data;
    vector->space = new_space;
  }

  match = (uint8_t *)vector->data + match_offset;
  memmove(match + member_size, match, bytes_after);

  vector->size++;
  return match;
}

ot_peer *vector_find_or_insert_peer(ot_vector *vector, ot_peer const *peer, size_t peer_size, int *exactmatch) {
  ot_peer *match;
  const size_t compare_size = OT_PEER_COMPARE_SIZE_FROM_PEER_SIZE(peer_size);
  size_t match_offset, bytes_after;

  if (vector->space < vector->size)
    vector = ((ot_vector *)vector->data) + vector_hash_peer(peer, compare_size, vector->size);
  match = vector_binary_search(peer, vector->data, vector->size, peer_size, compare_size, exactmatch);

  if (*exactmatch)
    return match;

  match_offset = vector->size ? (size_t)(match - (ot_peer *)vector->data) : 0;
  bytes_after = vector->size * peer_size - match_offset;

  if (vector->size + 1 > vector->space) {
    size_t new_space = vector->space ? OT_VECTOR_GROW_RATIO * vector->space : OT_VECTOR_MIN_MEMBERS;
    ot_peer *new_data = realloc(vector->data, new_space * peer_size);

    if (!new_data)
      return NULL;

    vector->data = new_data;
    vector->space = new_space;
  }

  match = (ot_peer *)vector->data + match_offset;
  memmove(match + peer_size, match, bytes_after);

  vector->size++;
  return match;
}

int vector_remove_peer(ot_vector *vector, ot_peer const *peer, size_t peer_size) {
  int exactmatch, was_seeder;
  ot_peer *match, *end;
  size_t compare_size = OT_PEER_COMPARE_SIZE_FROM_PEER_SIZE(peer_size);

  if (!vector->size)
    return 0;

  if (vector->space < vector->size)
    vector = ((ot_vector *)vector->data) + vector_hash_peer(peer, compare_size, vector->size);

  end = ((ot_peer *)vector->data) + peer_size * vector->size;
  match = (ot_peer *)vector_binary_search(peer, vector->data, vector->size, peer_size, compare_size, &exactmatch);
  if (!exactmatch)
    return 0;

  was_seeder = (OT_PEERFLAG_D(match, peer_size) & PEER_FLAG_SEEDING) ? 2 : 1;
  memmove(match, match + peer_size, end - match - peer_size);

  vector->size--;
  vector_fixup_peers(vector, peer_size);
  return was_seeder;
}

void vector_remove_torrent(ot_vector *vector, ot_torrent *match) {
  ot_torrent *end;

  if (!vector->size)
    return;

  end = ((ot_torrent *)vector->data) + vector->size;

  free_peerlist(match->peer_list);

  memmove(match, match + 1, sizeof(ot_torrent) * (end - match - 1));
  if ((--vector->size * OT_VECTOR_SHRINK_THRESH < vector->space) &&
      (vector->space >= OT_VECTOR_SHRINK_RATIO * OT_VECTOR_MIN_MEMBERS)) {
    void *new_data = realloc(vector->data, (vector->space / OT_VECTOR_SHRINK_RATIO) * sizeof(ot_torrent));
    if (new_data) {
      vector->space /= OT_VECTOR_SHRINK_RATIO;
      vector->data = new_data;
    }
  }
}

void vector_clean_list(ot_vector *vector, size_t num_buckets) {
  while (num_buckets--)
    free(vector[num_buckets].data);
  free(vector);
  return;
}

void vector_redistribute_buckets(ot_vector *peer_vector, size_t peer_size, size_t peer_count) {
  size_t bucket, bucket_size_new, num_buckets_new, num_buckets_old = 1;
  ot_vector *bucket_list_new, *bucket_list_old = peer_vector;
  int (*sort_func)(const void *, const void *) =
      peer_size == OT_PEER_SIZE6 ? &vector_compare_peer6 : &vector_compare_peer4;

  if (OT_VECTOR_HASBUCKETS(peer_vector)) {
    num_buckets_old = peer_vector->size;
    bucket_list_old = peer_vector->data;
  }

  if (peer_count < 255)
    num_buckets_new = 1;
  else if (peer_count > 8192)
    num_buckets_new = 64;
  else if (peer_count >= 512 && peer_count < 4096)
    num_buckets_new = 16;
  else if (peer_count < 512 && num_buckets_old <= 16)
    num_buckets_new = num_buckets_old;
  else if (peer_count < 512)
    num_buckets_new = 1;
  else if (peer_count < 8192 && num_buckets_old > 1)
    num_buckets_new = num_buckets_old;
  else
    num_buckets_new = 16;

  if (num_buckets_new == num_buckets_old)
    return;

  bucket_list_new = calloc(1, num_buckets_new * sizeof(ot_vector));
  if (!bucket_list_new)
    return;

  bucket_size_new = OT_VECTOR_MIN_MEMBERS;
  while (bucket_size_new * num_buckets_new < peer_count)
    bucket_size_new *= OT_VECTOR_GROW_RATIO;

  for (bucket = 0; bucket < num_buckets_new; ++bucket) {
    bucket_list_new[bucket].space = bucket_size_new;
    bucket_list_new[bucket].data = malloc(bucket_size_new * peer_size);
    if (!bucket_list_new[bucket].data) {
      vector_clean_list(bucket_list_new, num_buckets_new);
      return;
    }
  }

  for (bucket = 0; bucket < num_buckets_old; ++bucket) {
    ot_peer *peers_old = bucket_list_old[bucket].data;
    size_t peer_count_old = bucket_list_old[bucket].size;
    while (peer_count_old--) {
      ot_vector *bucket_dest = bucket_list_new;
      if (num_buckets_new > 1)
        bucket_dest += vector_hash_peer(peers_old, OT_PEER_COMPARE_SIZE_FROM_PEER_SIZE(peer_size), num_buckets_new);
      if (bucket_dest->size + 1 > bucket_dest->space) {
        void *tmp = realloc(bucket_dest->data, peer_size * OT_VECTOR_GROW_RATIO * bucket_dest->space);
        if (!tmp) {
          vector_clean_list(bucket_list_new, num_buckets_new);
          return;
        }
        bucket_dest->data = tmp;
        bucket_dest->space *= OT_VECTOR_GROW_RATIO;
      }
      memcpy((ot_peer *)bucket_dest->data + peer_size * bucket_dest->size++, peers_old, peer_size);
      peers_old += peer_size;
    }
  }

  for (bucket = 0; bucket < num_buckets_new; ++bucket)
    qsort(bucket_list_new[bucket].data, bucket_list_new[bucket].size, peer_size, sort_func);

  if (OT_VECTOR_HASBUCKETS(peer_vector))
    vector_clean_list((ot_vector *)peer_vector->data, peer_vector->size);
  else
    free(peer_vector->data);

  if (num_buckets_new > 1) {
    peer_vector->data = bucket_list_new;
    peer_vector->size = num_buckets_new;
    peer_vector->space = 0;
  } else {
    peer_vector->data = bucket_list_new->data;
    peer_vector->size = bucket_list_new->size;
    peer_vector->space = bucket_list_new->space;
    free(bucket_list_new);
  }
}

void vector_fixup_peers(ot_vector *vector, size_t peer_size) {
  int need_fix = 0;

  if (!vector->size) {
    free(vector->data);
    vector->data = NULL;
    vector->space = 0;
    return;
  }

  while ((vector->size * OT_VECTOR_SHRINK_THRESH < vector->space) &&
         (vector->space >= OT_VECTOR_SHRINK_RATIO * OT_VECTOR_MIN_MEMBERS)) {
    vector->space /= OT_VECTOR_SHRINK_RATIO;
    need_fix++;
  }
  if (need_fix) {
    void *new_data = realloc(vector->data, vector->space * peer_size);
    if (new_data)
      vector->data = new_data;
  }
}

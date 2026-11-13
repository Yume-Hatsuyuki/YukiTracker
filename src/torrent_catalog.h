#ifndef TORRENT_CATALOG_H
#define TORRENT_CATALOG_H
#include "trackerlogic.h"

enum catalog_kind { CATALOG_PAGE, CATALOG_TOP, CATALOG_NETWORKS, CATALOG_LOG, CATALOG_BUSY };
struct catalog_query {
  enum catalog_kind kind;
  unsigned limit, order;
  int has_cursor;
  ot_hash cursor;
};

int catalog_parse(struct catalog_query *query, const char *text, size_t length);
size_t catalog_render(char *out, size_t capacity, const struct catalog_query *query);
#endif

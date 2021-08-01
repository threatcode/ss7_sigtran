/*
 * lru-cache.c
 */
#include <stdio.h>
#include <string.h>
#include "uthash.h"

#define LRU_CACHE_MAX_SIZE 100000

typedef struct {
  char *key; /* always null terminated string */
  char *value;
  size_t vlen; /* length of value */
  UT_hash_handle hh;
} lru_cache_t;

void lru_cache_add(lru_cache_t *cache, char *key, char *value, size_t vlen)
{
  fprintf(stderr, "%s\n", __func__);
  lru_cache_t *entry, *tmp_entry;
  entry = malloc(sizeof(lru_cache_t));
  entry->key = strdup(key);
  entry->value = malloc(vlen);
  memcpy(entry->value, value, vlen);
  entry->vlen = vlen;
  HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(key), entry);

  /* prune the cache to MAX_CACHE_SIZE */
  if (HASH_COUNT(cache) >= LRU_CACHE_MAX_SIZE) {
    HASH_ITER(hh, cache, entry, tmp_entry) {
      /*
       * prune the first entry (loop is based on insertion order so this deletes the oldest item
       */
      HASH_DELETE(hh, cache, entry);
      free(entry->key);
      free(entry->value);
      free(entry);
      break;
    }
  }
}

char *lru_cache_find(lru_cache_t *cache, char *key, char **data, size_t *vlen)
{
  lru_cache_t *entry;
  HASH_FIND_STR(cache, key, entry);
  if (entry) {
    *data = entry->value;
    *vlen = entry->vlen;
    HASH_DELETE(hh, cache, entry);
    HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(key), entry);
    return entry->value;
  }
  return NULL;
}


#ifdef TEST_LRU_CACHE
int main(int argc, char *argv[])
{
  lru_cache_t *cache = NULL;
  lru_cache_add(cache, "ayub", "hello world", 12);
  char *val = NULL;
  size_t vlen;
  lru_cache_find(cache, "ayub", &val, &vlen);
  if (val) {
    fprintf(stderr, "Got value from cache: %s\n", val);
  }

  return 0;
}
#endif

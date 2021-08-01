/*
 * mph.c
 */
#include "mph.h"


/* ANSI C didn't have strdup() */
static char *my_strdup(const char *str, size_t len);

mph_tab_t *mph_load_file(const char *file)
{
  mph_tab_t *htab = NULL;
  mph_t *hash = NULL;
  FILE *fp = fopen(file, "r");
  if (!fp) return NULL;
  cmph_io_adapter_t *source = cmph_io_nlfile_adapter(fp);
  if (!source) return NULL;

  cmph_config_t *config = cmph_config_new(source);
  if (!config) return NULL;

  cmph_config_set_algo(config, CMPH_BDZ);
  hash = cmph_new(config);
  if (!hash) {
    fprintf(stderr, "Hash not created.\n");
  }
  cmph_config_destroy(config);
  cmph_io_nlfile_adapter_destroy(source);   

  if (hash) {
    htab = calloc(1, sizeof(htab));
    htab->hlen = cmph_size(hash);
    mph_key_t *keys = malloc(htab->hlen * sizeof(mph_key_t));
    rewind(fp);
    char buf[128];
    size_t len = 0;
    unsigned int i = 0;
    while (fgets(buf, sizeof(buf), fp)) {
      len = strlen(buf); /* just in load time, no performance penalty */
      if (buf[len-1] == '\n') { buf[len-1] = '\0'; --len; }
      i = cmph_search(hash, buf, len);
      keys[i].key = my_strdup(buf, len);
      keys[i].klen = len;
    }
    htab->keys = keys;
    htab->hash = hash;
  }
  fclose(fp);

  return htab;
}

/* get the mph_key_t * */
mph_key_t *mph_search_key(mph_tab_t *htab, const char *key, size_t klen)
{
  if (!htab) return NULL;
  mph_t *hash = htab->hash;
  if (!hash) return NULL;
  mph_key_t *keys = htab->keys;
  unsigned int id = cmph_search(hash, key, klen);
  if (keys[id].klen == klen && strncmp(keys[id].key, key, (klen > keys[id].klen? klen:keys[id].klen)) == 0)
    return (keys+id);
  return NULL;
}

/* get the ID of the hash generated */
/* returns negative in case of error/not-found */
int mph_search_key_id(mph_tab_t *htab, const char *key, size_t klen)
{
  if (!htab) return -1;
  mph_t *hash = htab->hash;
  if (!hash) return -2;
  mph_key_t *keys = htab->keys;
  unsigned int id = cmph_search(hash, key, klen);
  if (keys[id].klen == klen && strncmp(keys[id].key, key, (klen > keys[id].klen? klen:keys[id].klen)) == 0)
    return id;
  return -3;
}

/* get the mph_key_t * */
mph_key_t *mph_search_id(mph_tab_t *htab, unsigned int id)
{
  if (!htab) return NULL;
  if (id >= htab->hlen) return NULL;
  return (htab->keys+id);
}

void mph_unload(mph_tab_t *htab)
{
  int i;
  if (!htab) return;

  if (htab->hash) cmph_destroy(htab->hash);
  for (i = 0; i < htab->hlen; ++i) {
    free(htab->keys[i].key);
  }
  free(htab->keys);
  free(htab);
}

static char *my_strdup(const char *str, size_t len)
{
  char *dst = malloc(len+1);
  memcpy(dst, str, len+1);
  dst[len] = '\0'; /* confirm that there's terminating nul char */
  return dst;
}



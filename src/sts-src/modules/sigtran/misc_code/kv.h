/*
 * kv.h
 */
#ifndef _KV_H_
#define _KV_H_
#include "defs.h"
#include <stdlib.h>

typedef struct {
  char *key;
  uint64_t key_len;
  char *val;
  uint64_t val_len;
} kv_t;

void kv_free(kv_t *kv);

#endif

/*
 * kv.c
 */
#include "kv.h"

void kv_free(kv_t *kv)
{
  if (!kv) return;

  if (kv->key) free(kv->key);
  if (kv->val) free(kv->val);
  free(kv);
}

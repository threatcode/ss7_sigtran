/*
 * iarray-test.c
 * tests iarray functions
 */
#include <stdio.h>
#include <stdlib.h>

#include "iarray.h"

int main(void)
{
  iarray_t *a = NULL;
  int ret = 0;

  int i = 0;

  iarray_key_t key = 0;
  iarray_key_t pkey = 0;

  iarray_val_t val = 5;

  ret = iarray_init(&a); /* always succeeds, caz it just sets to NULL */

  for (i = 5; i >= 0; --i) {
    key = i;
    //key = i;
    //val = i;
    if (iarray_put(&a, key, val) != -1) {
      ret = iarray_get(a, key, &val);
      if (ret > 0) fprintf(stderr, "(%lu,%lu)\n", key, val);
      //iarray_del(&a, key);
    } else {
      fprintf(stderr, "iarray_put failed\n");
    }
  }

  iarray_key_t refkey = 0;

  pkey = 0;
  refkey = 5;
  //ret = iarray_get_prev_empty_key(a, refkey, &pkey);
  ret = iarray_get_last_empty_key(a, refkey, &pkey);
  if (ret == 1) {
    fprintf(stderr, "key %lu is last empty key before key %lu\n", pkey, refkey);
    ret = iarray_get(a, pkey, &val);
    if (ret > 0) fprintf(stderr, "(%lu,%lu)\n", pkey, val);
  } else {
    fprintf(stderr, "No empty key before %lu\n", refkey);
    refkey -= 2;
    fprintf(stderr, "Deleting key %lu\n", refkey);
    iarray_del(&a, refkey);
    refkey += 2;
    fprintf(stderr, "Deleting key %lu\n", refkey);
    iarray_del(&a, refkey);
  }

  pkey = 0;
  refkey = 5;
  //ret = iarray_get_prev_empty_key(a, refkey, &pkey);
  ret = iarray_get_last_empty_key(a, refkey, &pkey);
  if (ret == 1) {
    fprintf(stderr, "key %lu is last empty key before key %lu\n", pkey, refkey);
    ret = iarray_get(a, pkey, &val);
    if (ret > 0) fprintf(stderr, "(%lu,%lu)\n", pkey, val);
  } else {
    refkey--;
    fprintf(stderr, "Deleting key %lu\n", refkey);
    iarray_del(&a, refkey);
  }

  pkey = 0;
  refkey = 6;
  //ret = iarray_get_prev_empty_key(a, refkey, &pkey);
  ret = iarray_get_last_empty_key(a, refkey, &pkey);
  if (ret == 1) {
    fprintf(stderr, "key %lu is last empty key before key %lu\n", pkey, refkey);
    ret = iarray_get(a, pkey, &val);
    if (ret > 0) fprintf(stderr, "(%lu,%lu)\n", pkey, val);
  }

  size_t count = 0;
  ret = iarray_count(a, &count);
  fprintf(stderr, "Total %lu keys in the array\n", count);

  iarray_walk_forward(&a, iarray_walk_func_print, NULL);

  iarray_free(&a);

  return 0;
}

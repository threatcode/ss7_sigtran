/*
 * iarray.h
 */
#ifndef __IARRAY_H__
#define __IARRAY_H__

#include <inttypes.h>

typedef void iarray_t;

/* Make sure following are both of size of Word_t (as in Judy.h)
 * otherwise unexpected results may take place
 */
typedef unsigned long iarray_key_t;
typedef unsigned long iarray_val_t; /* can be pointer as well (cast accordingly) */

typedef struct {
  iarray_t **iarray;
  iarray_key_t key;
  iarray_val_t *pval;
} iarray_walk_data_t;

typedef void (*iarray_walk_func_t)(iarray_walk_data_t *pwdata, void *userdata);

int iarray_walk_forward(iarray_t **iarray, iarray_walk_func_t walk_func, void *userdata);
int iarray_walk_backward(iarray_t **iarray, iarray_walk_func_t walk_func, void *userdata);

/* Array Utility functions (Using Judy Array with Integer keys [JudyL]) */
/* when array is modified, the array pointer must be sent */
int iarray_init(iarray_t **iarray);
int iarray_free(iarray_t **parray);
int iarray_get(iarray_t *array, iarray_key_t key, iarray_val_t *pval);
int iarray_put(iarray_t **parray, iarray_key_t key, iarray_val_t val);
int iarray_del(iarray_t **parray, iarray_key_t key);
int iarray_count(iarray_t *array, size_t *count);
int iarray_count_between(iarray_t *array, iarray_key_t key1, iarray_key_t key2, size_t *count);
#if 0
int iarray_get_first_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *pkey, iarray_val_t *pval);
int iarray_get_next_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *pkey, iarray_val_t *pval);
int iarray_get_last_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast, iarray_val_t *pval);
int iarray_get_prev_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast, iarray_val_t *pval);
#endif
int iarray_get_first_empty_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast);
int iarray_get_next_empty_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast);
int iarray_get_last_empty_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast);
int iarray_get_prev_empty_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast);
void iarray_walk_func_print(iarray_walk_data_t *pwdata, void *userdata);


#endif

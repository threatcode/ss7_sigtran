/*
 * iarray.c
 * indexed array (dynamic) using JudyL functions
 * don't mess with pointers unless you maintain the pointers and values of same sized variables
 */
#include <stdio.h>
#include "iarray.h"
#include <Judy.h>
#include "defs.h"

/* each routine returns 1 for success, -1 for failure */


int iarray_init(iarray_t **iarray)
{
  if (!iarray) return -1;

  *iarray = NULL;
  return 1;
}

int iarray_free(iarray_t **parray)
{
  if (!parray || !*parray) return -1; /* nothing in array */

  JudyLFreeArray(parray, NULL);
  //JLFA(Rc_word, PJLArray);
  return 1;
}

/* get value associated with key */
int iarray_get(iarray_t *array, iarray_key_t key, iarray_val_t *pval)
{
  if (!array) return -1;

  Word_t Index;
  PPvoid_t PValue;
  Pvoid_t PJLArray = (Pvoid_t) array;

  Index = (Word_t) key;


  //JLG(PValue, PJLArray, Index);
  PValue = JudyLGet(PJLArray, Index, NULL);
  if (PValue == PJERR) return -1;
  if (PValue == NULL) return -1;

  *pval = (iarray_val_t) *PValue;

  return 1;
}


/* associate value with key and return value */
int iarray_put(iarray_t **parray, iarray_key_t key, iarray_val_t val)
{
  if (!parray) return -1;

  Word_t Index;
  Word_t Value;
  PPvoid_t PValue;

  Index = (Word_t) key;
  Value = (Word_t) val;

  PValue = JudyLIns(parray, Index, NULL);
  //JLI(PValue, PJLArray, Index);
  if (PValue == PJERR) return -1;
  if (PValue == NULL) return -1;

  *PValue = (Pvoid_t) Value;

  return 1;
}


/* delete key-value pair from array */
int iarray_del(iarray_t **parray, iarray_key_t key)
{
  if (!parray || !*parray) return -1;
  Word_t Index;
  int Rc_int;

  Index = (Word_t) key;

  Rc_int = JudyLDel(parray, Index, NULL);
  //JLD(Rc_int, PJLArray, Index);
  if (Rc_int == 0) return -1;
  return 1;
}

/* count number of indexes present in the array */
/* return -1 if error, count otherwise */
int iarray_count(iarray_t *array, size_t *count)
{
  if (!array) return -1;

  *count = JudyLCount(array, 0, -1, NULL);

  return 1;
}


/* count number of indexes present in the array, in between index1 and index 2 */
/* return -1 if error, count otherwise */
int iarray_count_between(iarray_t *array, iarray_key_t key1, iarray_key_t key2, size_t *count)
{
  if (!array) return -1;

  *count = JudyLCount(array, key1, key2, NULL);

  return 1;
}


#if 0
/* find an empty key/index which is greater than the refkey */
/* inclusive */
int iarray_get_first_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *pkey, iarray_val_t *pval)
{
  iarray_key_t key = refkey;
  //JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  pval = JudyLFirst(array, (Word_t *) &key, NULL);
  if (pval == NULL || pval == PJERR) return -1;

  *pkey = key;
  //fprintf(stderr, "key=%u, refkey=%u\n", key, refkey);
  return 1;
}

/* find an empty key/index which is greater than the refkey */
/* exclusive */
int iarray_get_next_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *pkey, iarray_val_t *pval)
{
  iarray_key_t key = refkey;
  //JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  pval = (PPvoid_t) JudyLNext(array, (Word_t *) &key, NULL);
  if (pval == NULL || pval == PJERR) return -1;

  *pkey = key;
  //fprintf(stderr, "key=%u, refkey=%u\n", key, refkey);
  return 1;
}

/* find an empty key/index which is lower than the refkey */
/* inclusive */
int iarray_get_last_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *pkey, iarray_val_t *pval)
{
  iarray_key_t key = refkey;
  //JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  pval = JudyLLast(array, (Word_t *) &key, NULL);
  if (pval == NULL || pval == PJERR) return -1;

  *pkey = key;
  //fprintf(stderr, "key=%u, refkey=%u\n", key, refkey);
  return 1;
}

/* find an empty key/index which is lower than the refkey */
/* exclusive */
int iarray_get_prev_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *pkey, iarray_val_t *pval)
{
  iarray_key_t key = refkey;
  //JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  pval = JudyLPrev(array, (Word_t *) &key, NULL);
  if (pval == NULL || pval == PJERR) return -1;
  *pkey = key;

  //fprintf(stderr, "key=%u, refkey=%u\n", key, refkey);
  return 1;
}

#endif

/* find an empty key/index which is greater than the refkey */
/* inclusive */
int iarray_get_first_empty_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast)
{
  iarray_key_t key = refkey;
  int ret = -1;
  //JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  ret = JudyLFirstEmpty(array, (Word_t *) &key, NULL);
  if (ret == 1) {
    *plast = key;
    //fprintf(stderr, "key=%u\n", key);
  } else {
    ret = -1;
    //fprintf(stderr, "key=%u\n", key);
  }
  //fprintf(stderr, "key=%u, refkey=%u\n", key, refkey);
  return ret;
}


/* find an empty key/index which is greater than the refkey */
/* exclusive */
int iarray_get_next_empty_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast)
{
  iarray_key_t key = refkey;
  int ret = -1;
  //JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  ret = JudyLNextEmpty(array, (Word_t *) &key, NULL);
  if (ret == 1) {
    *plast = key;
    //fprintf(stderr, "key=%u\n", key);
  } else {
    ret = -1;
    //fprintf(stderr, "key=%u\n", key);
  }
  //fprintf(stderr, "key=%u, refkey=%u\n", key, refkey);
  return ret;
}


/* find an empty key/index which is lower than the refkey */
/* inclusive */
int iarray_get_last_empty_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast)
{
  iarray_key_t key = refkey;
  int ret = -1;
  //JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  ret = JudyLLastEmpty(array, (Word_t *) &key, NULL);
  if (ret == 1) {
    *plast = key;
    //fprintf(stderr, "key=%u\n", key);
  } else {
    ret = -1;
    //fprintf(stderr, "key=%u\n", key);
  }
  //fprintf(stderr, "key=%u, refkey=%u\n", key, refkey);
  return ret;
}

/* find an empty key/index which is lower than the refkey */
/* exclusive */
int iarray_get_prev_empty_key(iarray_t *array, iarray_key_t refkey, iarray_key_t *plast)
{
  iarray_key_t key = refkey;
  int ret = -1;
  key = refkey;
  //JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  ret = JudyLPrevEmpty(array, (Word_t *) &key, NULL);
  if (ret == 1) {
    *plast = key;
    //fprintf(stderr, "key=%u\n", key);
  } else {
    ret = -1;
    //fprintf(stderr, "key=%u\n", key);
  }
  //fprintf(stderr, "key=%u, refkey=%u\n", key, refkey);
  return ret;
}

int iarray_walk_forward(iarray_t **iarray, iarray_walk_func_t walk_func, void *userdata)
{
  Word_t Index;
  PWord_t PValue;
  Pvoid_t PJLArray = *iarray;
  iarray_walk_data_t *pwdata = MYCALLOC(1, sizeof(iarray_walk_data_t));

  Index = 0;
  JLF(PValue, PJLArray, Index);
  while (PValue != NULL) {
    pwdata->iarray = iarray;
    pwdata->key = Index;
    pwdata->pval = PValue;
    walk_func(pwdata, userdata);
    JLN(PValue, PJLArray, Index);
  }

  MYFREE(pwdata);

  return 1;
}

int iarray_walk_backward(iarray_t **iarray, iarray_walk_func_t walk_func, void *userdata)
{
  Word_t Index;
  PWord_t PValue;
  Pvoid_t PJLArray = *iarray;
  iarray_walk_data_t *pwdata = MYCALLOC(1, sizeof(iarray_walk_data_t));

  Index = 0;
  JLL(PValue, PJLArray, Index);
  while (PValue != NULL) {
    pwdata->iarray = iarray;
    pwdata->key = Index;
    pwdata->pval = PValue;
    walk_func(pwdata, userdata);
    JLP(PValue, PJLArray, Index);
  }

  MYFREE(pwdata);

  return 1;
}

void iarray_walk_func_print(iarray_walk_data_t *pwdata, void *userdata)
{
  fprintf(stderr, "key = %lu, val = %lu\n", pwdata->key, *pwdata->pval);
}


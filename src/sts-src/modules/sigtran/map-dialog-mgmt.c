/*
 * map_dialog_mgmt.c
 * MAP dialogue management code
 */
#include "map-dialog-mgmt.h"
#include "sigtran_tcap.h"

inline uint32_t get_tid(uint16_t map_id, uint16_t dialogue_id)
{
  return map_id << 16 | dialogue_id;
}

inline uint16_t tid2map_id(uint32_t tid)
{
  return tid >> 16;
}

inline uint16_t tid2dialogue_id(uint32_t tid)
{
  return tid & 0xffff;
}

int map_get_next_dialogue(map_t *map, uint16_t n, uint16_t *next_dialogue)
{
  FTRACE();
  int ret = -1;

  //uint16_t next_dialogue = 0;
  iarray_key_t tmpkey = 0;
#define MAX_MAP_DIALOGUES		0xffff
  //return map->last_dialogue[n]++;
  pthread_rwlock_rdlock(&map->rwlocks[n]);
  ret = iarray_get_last_empty_key(map->dialogues[n], MAX_MAP_DIALOGUES, &tmpkey);
  pthread_rwlock_unlock(&map->rwlocks[n]);
  if (ret == -1) return ret;
  *next_dialogue = (uint16_t) tmpkey;

  return ret;
}

int map_set_dialogue(map_t *map, uint16_t n, iarray_key_t key, iarray_val_t val)
{
  FTRACE();
  int ret = -1;
  pthread_rwlock_wrlock(&map->rwlocks[n]);
  ret = iarray_put(&map->dialogues[n], key, val);
  pthread_rwlock_unlock(&map->rwlocks[n]);

  return ret;
}

/* get and set in one shot, so that there can be no inconsistent condition between two calls */
int map_set_next_dialogue(map_t *map, uint16_t n, iarray_val_t *val, uint16_t *next_dialogue)
{
  FTRACE();
  int ret = -1;

  iarray_key_t tmpkey = 0;

  pthread_rwlock_wrlock(&map->rwlocks[n]);
  ret = iarray_get_last_empty_key(map->dialogues[n], MAX_MAP_DIALOGUES, &tmpkey);
  if (ret == -1) goto err;
  *next_dialogue = (uint16_t) tmpkey;
  *val = (iarray_val_t) MYCALLOC(1, sizeof(tcap_session_t));
  //fprintf(stderr, "Allocated tcsess @ %p\n", (void *) *val);
  ret = iarray_put(&map->dialogues[n], tmpkey, *val);
  DTRACE("Allocated Dialogue {map_id=%u, dialog_id=%u}\n", n, (uint16_t) tmpkey);

err:
  pthread_rwlock_unlock(&map->rwlocks[n]);

  return ret;
}



int map_get_dialogue(map_t *map, uint16_t n, iarray_key_t key, iarray_val_t *val)
{
  FTRACE();
  int ret = -1;
  pthread_rwlock_rdlock(&map->rwlocks[n]);
  ret = iarray_get(map->dialogues[n], key, val);
  pthread_rwlock_unlock(&map->rwlocks[n]);

  return ret;
}

int map_del_dialogue(map_t *map, uint16_t n, iarray_key_t key)
{
  FTRACE();
  int ret = -1;
  iarray_val_t val = 0;
  pthread_rwlock_wrlock(&map->rwlocks[n]);
  ret = iarray_get(map->dialogues[n], key, &val);
  if (ret >= 0) {
    DTRACE("Freeing Dialogue {map_id=%u, dialog_id=%u}\n", n, (uint16_t) key);
    if (val) {
      //fprintf(stderr, "Freeing tcsess %p\n", (void *) val);
      MYFREE((void *) val); /* tcap session (tcsess) */
    }
    ret = iarray_del(&map->dialogues[n], key);
  }
  pthread_rwlock_unlock(&map->rwlocks[n]);

  return ret;
}

#if 0
int map_print_dialogue_summary(map_t *map, uint16_t n, char *buf, size_t buflen)
{
  FTRACE();
  int ret = -1;
  size_t count = 0;
#if 0
  struct userdata {
    char *buf;
    size_t size;
  } udata;
  udata.buf = buf;
  udata.size = buflen;
#endif

  pthread_rwlock_rdlock(&map->rwlocks[n]);
  ret = iarray_count(map->dialogues[n], &count);
//  iarray_walk_backward(&map->dialogues[n], walk_func, &udata);
  pthread_rwlock_unlock(&map->rwlocks[n]);
  memset(buf, 0, buflen);
  if (ret >= 0) {
    ret = snprintf(buf, buflen-1, "Currently running dialogues on MAP Stack [%u]: %lu\n", n, count);
  } else {
    ret = snprintf(buf, buflen-1, "Error getting statistics from MAP Stack. Please try later.");
  }

  return ret;
}
#endif

size_t map_get_dialogue_count(map_t *map, uint16_t n)
{
  FTRACE();
  size_t count = 0;

  if (!map) return 0;

  pthread_rwlock_rdlock(&map->rwlocks[n]);
  (void) iarray_count(map->dialogues[n], &count);
  pthread_rwlock_unlock(&map->rwlocks[n]);

  return count;
}

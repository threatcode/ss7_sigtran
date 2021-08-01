/*
 * map_dialog_mgmt.h
 */
#ifndef _MAP_DIALOG_MGMT_H_
#define _MAP_DIALOG_MGMT_H_

#include "mod_sigtran.h"

uint32_t get_tid(uint16_t map_id, uint16_t dialogue_id);
uint16_t tid2map_id(uint32_t tid);
uint16_t tid2dialogue_id(uint32_t tid);
int map_get_next_dialogue(map_t *map, uint16_t n, uint16_t *next_dialogue);
int map_set_dialogue(map_t *map, uint16_t n, iarray_key_t key, iarray_val_t val);
/* do the above two operation in one shot */
int map_set_next_dialogue(map_t *map, uint16_t n, iarray_val_t *val, uint16_t *next_dialogue);

int map_get_dialogue(map_t *map, uint16_t n, iarray_key_t key, iarray_val_t *val);
int map_del_dialogue(map_t *map, uint16_t n, iarray_key_t key);
size_t map_get_dialogue_count(map_t *map, uint16_t n);

#endif

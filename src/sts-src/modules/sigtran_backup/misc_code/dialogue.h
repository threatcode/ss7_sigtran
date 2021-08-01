/*
 * dialogue.h
 */
#ifndef _DIALOGUE_H_
#define _DIALOGUE_H_

typedef struct {
  uint16_t did; /* dialogue id */
  uint32_t gw_tid; /* originating transaction id, for tcap layer */
  uint32_t nt_tid; /* destination transaction id, for tcap layer */
  uint8_t momt; /* mo=0, mt=1 */
  void *data; /* this will point to m3ua return packet */
} dialogue_t;



#endif

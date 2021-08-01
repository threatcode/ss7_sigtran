/*
 * sigtran_tcap.h
 */
#ifndef _SIGTRAN_TCAP_H_
#define _SIGTRAN_TCAP_H_

#include "iarray.h"

typedef struct {
#define MOMT_MO		0
#define MOMT_MT		1
  uint8_t momt;
  char momt_desc[3];
  uint8_t flow; /* enum {begin,continue,end,abort} */
  char flow_desc[10];
  uint32_t hlr_tid; /* hlr tid */
  uint32_t ugw_tid; /* ugw tid */
  long opcode;
  uint8_t dialog_pdu_needed;

  time_t start_time;
  time_t heartbeat;
  int8_t invokeid; /* invoke id will be decremented in each response */

  long end_opcode;
  long end_invokeid;

  char msisdn[20]; /* store it throughout the session */
  uint8_t msisdn_len;
  uint8_t aborted; /* is session aborted? */
  uint8_t error; /* is error occurred in MT? */
  uint8_t finished; /* is session finished */
} tcap_session_t;

#endif

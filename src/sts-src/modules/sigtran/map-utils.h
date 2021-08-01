/*
 * map-utils.h
 */
#ifndef _MAP_UTILS_H_
#define _MAP_UTILS_H_

#include "mod_sigtran.h"
#include "GSMMAPOperationLocalvalue.h"
#include "USSD-Arg.h"
#include "AnyTimeInterrogationArg.h"
#include "MAP-DialoguePDU.h"

#include <asn_internal.h>		/* FREEMEM(), etc. */

#include "sigtran_tcap.h"
#include "dialogue-utils.h"

#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>
//#include "gsm.h"
#include "utils.h"


typedef struct {
  tcap_session_t *tcsess;

  uint8_t is_ati;
  long age_of_location;
  char vlr_no[15];
  uint16_t mcc;
  uint16_t mnc;
  uint16_t lac; /* CellGlobalIdOrServiceAreaIdFixedLength ::= OCTET STRING (SIZE (7)) [ octets 4,5 LAC, octets 6,7 CI ] */
  uint16_t ci; /* CellGlobalIdOrServiceAreaIdFixedLength ::= OCTET STRING (SIZE (7)) [ octets 4,5 LAC, octets 6,7 CI ] */

  uint16_t map_stack_id;
  uint16_t dialogue_id;
  uint8_t dcs; /* 0x0f means {b0000=coding group, default gsm 7 bit alphabet, 1111=language unspecified} */
  char ussd_string[SIGTRAN_MTU]; /* will initialize it as null-terminated */
  uint8_t ussd_string_len; /* how many octets (bytes) */
  char msisdn[20]; /* will initialize it as null-terminated */
  uint8_t msisdn_len;

} ussd_session_t;


Component_t *sigtran_create_map_comp(tcap_session_t *tcsess,
    int comp_type, asn_TYPE_descriptor_t *td, void *sptr);
USSD_Arg_t *map_build_ussd_arg(const char *msg, const char *msisdn);
AnyTimeInterrogationArg_t *map_build_ati_arg(const char *msisdn, const char *gsmscf_addr);
void map_free_ussd_arg(USSD_Arg_t *arg);
void map_free_ati_arg(AnyTimeInterrogationArg_t *arg);
Component_t *ati_session_comp_build(tcap_session_t *tcsess, const char *gsmscf_addr, const char *msisdn, int flow, int notify_only);
Component_t *ussd_session_comp_build(tcap_session_t *tcsess, const char *msg, const char *msisdn, int flow, int notify_only);
void ati_session_comp_free(Component_t *comp);
void ussd_session_comp_free(Component_t *comp);
void ussd_session_dump(ussd_session_t *info);


#endif

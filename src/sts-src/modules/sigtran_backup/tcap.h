/*
 * tcap.h
 * ITU Q.773
 */
#ifndef _TCAP_H_
#define _TCAP_H_

#include "defs.h"
#include <TCMessage.h>
#include "Invoke.h"
#include "USSD-Arg.h"
#include <constr_TYPE.h>

void tcap_free(TCMessage_t *pdu);
void tcap_print(TCMessage_t *pdu);

TCMessage_t *tcap_decode(const void *buf, size_t len);
//void tcap_encode(TCMessage_t *tcm, out_t *out);
void *inap_decode(Invoke_t *invoke, asn_TYPE_descriptor_t **type);
//int tcap_extract_from_buf(const char *buf, size_t len, const char *spec, out_t *out);
//int tcap_extract_from_struct(TCMessage_t *tcm, const char *spec, out_t *out);
//int inap_extract_from_buf(const char *buf, size_t len, const char *spec, out_t *out);
//int inap_extract(TCMessage_t *tcm, size_t len, const char *spec, out_t *out);

USSD_Arg_t *ussd_decode(const void *buf, size_t len);
void ussd_free(USSD_Arg_t *pdu);
void ussd_print(USSD_Arg_t *pdu);
//int ussd_extract_from_buf(const char *buf, size_t len, const char *spec, out_t *out);
//int ussd_extract_from_struct(USSD_Arg_t *pdu, const char *spec, out_t *out);


#endif

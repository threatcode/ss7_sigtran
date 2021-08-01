/*
 * sccp.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "sccp.h"
#include "utils.h"


int sccp_called_party(uint8_t ssn, const char *gt, sccp_called_party_address_t *called)
{
  uint8_t nextpos = 0;

  called->ai.reserved = 0x0;
  called->ai.routing_indicator = 0x0; /* route on GT (should be configurable) */
  called->ai.global_title_indicator = 0x4; /* route on GT (should be configurable) */
  called->ai.ssn_indicator = 0x1; /* route on GT (should be configurable) */
  called->ai.point_code_indicator = 0x0; /* route on GT (should be configurable) */

  called->ssn = ssn; /* HLR */
  called->gt.translation_type = 0x00;
  called->gt.encoding_scheme = 0x2; /* BCD */
  called->gt.numbering_plan = 0x1; /* ISDN/telephony */
  called->gt.reserved = 0x0; /* ISDN/telephony */
  called->gt.nai = 0x04; /* International Number */
  encode_called_party(gt, strlen(gt), called->gt.digits, &nextpos);

  return 0;
}

#define sccp_calling_party(ssn, gt, called) sccp_called_party((ssn), (gt), (called))




/* sccp utility functions */
sccp_data_udt_t *sccp_build_udt(uint8_t called_ssn, const char *called_gt, uint8_t calling_ssn, const char *calling_gt,
    octet *data, uint16_t datalen)
{
  sccp_data_udt_t *udt = NULL;
  
  udt = MYCALLOC(1, sizeof(sccp_data_udt_t));
  if (!udt) return NULL;

  udt->mtype = SCCP_MSG_TYPE_UDT;
  udt->pclass = 0x00; /* class */
  udt->mhndl = 0x00; /* message handling: no special options */
  udt->variable_called = 3; /* currently hard coded, later on will be configurable */
  udt->variable_calling = 14; /* currently hard coded, later on will be configurable */
  udt->variable_data = 25; /* currently hard coded, later on will be configurable */

  udt->called_len = sizeof(sccp_called_party_address_t);
  sccp_called_party(called_ssn, called_gt, &udt->called);
  udt->calling_len = sizeof(sccp_calling_party_address_t);
  sccp_calling_party(calling_ssn, calling_gt, &udt->calling);
  udt->data_len = datalen;
  memcpy(udt->data, data, datalen);

  return udt;
}

/* pack sccp to byte-stream */
octet *sccp_udt2octet(sccp_data_udt_t *udt, uint32_t *nextpos)
{
  uint32_t len = 0;
  octet *ret = NULL;
  if (nextpos) *nextpos = 0;

  if (!udt) return NULL;

  len = 2+3+1+udt->called_len+1+udt->calling_len+1+udt->data_len;
  ret  = MYCALLOC(1, len);
  if (!ret) return NULL;

  memcpy(ret, udt, len);
  if (nextpos) *nextpos = len;

#if 0
  uint16_t i;

  ret  = MYCALLOC(1, sizeof(uint8_t) + sizeof(uint8_t) + udt->variable_called + udt->variable_calling + udt->variable_data);

  i = 0;
  tlv->tag = htons(tlv->tag);
  memcpy((ret+i), &tlv->tag, 2);
  i += 2;
  tlv->len = htons(tlv->len);
  memcpy((ret+i), &tlv->len, 2);
  i += 2;
  memcpy((ret+i), tlv->val, len-4); /* len - tag_len - len_len */

  *nextpos = len+rem;

#endif
  return ret;
}

/* FIXME: following assumes that the gt.digits are exactly 6 bytes. Need to be more robust in future. */
/* nextpos helps us rescan the buffer for more TLVs */
sccp_data_udt_t *sccp_octet2udt(octet *buf, uint16_t buflen, uint32_t *nextpos)
{
  sccp_data_udt_t *udt = NULL;
  if (nextpos) *nextpos = 0;

  if (!buf || buflen < 27 || buflen > SIGTRAN_MTU) return NULL;

  udt = MYCALLOC(1, sizeof(sccp_data_udt_t));
  memcpy(udt, buf, buflen);

  if (nextpos) *nextpos = buflen;

  return udt;

#if 0
  uint16_t i;
  uint8_t val;

  i = 0;

  /*
  memcpy(&udt->mtype, buf+i, 1);
  i += 1;
  */
  udt->mtype = buf[i++];

  /*
  memcpy(&val, buf+i, 1);
  i += 1;
  */
  val = buf[i++];
  udt->pclass = (val << 4) >> 4;
  udt->mhndl = (val >> 4);

  udt->variable_called = buf[i++];
  /*
  memcpy(&udt->variable_called, buf+i, 1);
  i += 1;
  */

  udt->variable_calling = buf[i++];
  /*
  memcpy(&udt->variable_calling, buf+i, 1);
  i += 1;
  */

  udt->variable_data = buf[i++];
  /*
  memcpy(&udt->variable_data, buf+i, 1);
  i += 1;
  */


  udt->called_len = buf[i++];

  memcpy(&udt->called.ai, buf+i, 1);
  i += 1;

  udt->called.ssn = buf[i++];
  /*
  memcpy(&udt->called.ssn, buf+i, 1);
  i += 1;
  */

  udt->called.gt.translation_type = buf[i++];
  /*
  memcpy(&udt->called.gt.translation_type, buf+i, 1);
  i += 1;
  */

  /*
  memcpy(&val, buf+i, 1);
  i += 1;
  */
  val = buf[i++];
  udt->called.gt.numbering_plan = val >> 4;
  udt->called.gt.encoding_scheme = val & 0x0f;

  /*
  memcpy(&val, buf+i, 1);
  i += 1;
  */
  val = buf[i++];
  udt->called.gt.nai = val & 0x8f; /* MSB to be emptied */

  memcpy(udt->called.gt.digits, buf+i, 6);
  i += 6;


  udt->calling_len = buf[i++];

  memcpy(&udt->calling.ai, buf+i, 1);
  i += 1;

  udt->calling.ssn = buf[i++];
  /*
  memcpy(&udt->calling.ssn, buf+i, 1);
  i += 1;
  */

  udt->calling.gt.translation_type = buf[i++];
  /*
  memcpy(&udt->calling.gt.translation_type, buf+i, 1);
  i += 1;
  */

  /*
  memcpy(&val, buf+i, 1);
  i += 1;
  */
  val = buf[i++];
  udt->calling.gt.numbering_plan = val >> 4;
  udt->calling.gt.encoding_scheme = val & 0x0f;

  /*
  memcpy(&val, buf+i, 1);
  i += 1;
  */
  val = buf[i++];
  udt->calling.gt.nai = val & 0x8f; /* MSB to be emptied */

  memcpy(udt->calling.gt.digits, buf+i, 6);
  i += 6;

  udt->data_len = buf[i++];
  memcpy(udt->data, buf+i, buflen-i);
  i += buflen - i;

  *nextpos = i;
#endif
}

/* print bcd encoded digits */
void sccp_print_digits(uint8_t *digits, uint8_t len)
{
  uint8_t i = 0;
  for (i = 0; i < len; ++i) {
    fprintf(stdout, "%x%x",  digits[i] & 0x0f, (digits[i] & 0xf0) >> 4);
  }
  fprintf(stdout, "\n");
}

void sccp_dump_udt(sccp_data_udt_t *udt)
{
  if (!udt) return;

  fprintf(stdout, "Message Type: 0x%02x (%u)\n", udt->mtype, udt->mtype);
  fprintf(stdout, "Message Class: 0x%02x (%u)\n", udt->pclass, udt->pclass);
  fprintf(stdout, "Message Handling: 0x%02x (%u)\n", udt->mhndl, udt->mhndl);
  fprintf(stdout, "Location of Called Party address: 0x%02x (%u)\n", udt->variable_called, udt->variable_called);
  fprintf(stdout, "Location of Calling Party address: 0x%02x (%u)\n", udt->variable_calling, udt->variable_calling);
  fprintf(stdout, "Location of User Data: 0x%02x (%u)\n", udt->variable_data, udt->variable_data);

  fprintf(stdout, "Called Party Address: %u bytes\n", udt->called_len);
  fprintf(stdout, "- Address Indicator:\n");
  fprintf(stdout, "-- Routing Indicator: 0x%02x\n", udt->called.ai.routing_indicator);
  fprintf(stdout, "-- Global Title Indicator: 0x%02x\n", udt->called.ai.global_title_indicator);
  fprintf(stdout, "-- SubsyStem Number Indicator: 0x%02x\n", udt->called.ai.ssn_indicator);
  fprintf(stdout, "-- Point Code Indicator: 0x%02x\n", udt->called.ai.point_code_indicator);
  fprintf(stdout, "- SubSystem Number: %u (0x%02x)\n", udt->called.ssn, udt->called.ssn);
  fprintf(stdout, "- Global Title:\n");
  fprintf(stdout, "-- Translation Type: 0x%02x\n", udt->called.gt.translation_type);
  fprintf(stdout, "-- Numbering Plan: 0x%02x\n", udt->called.gt.numbering_plan);
  fprintf(stdout, "-- Encoding Scheme: 0x%02x\n", udt->called.gt.encoding_scheme);
  fprintf(stdout, "-- Nature of Address Indicator: 0x%02x\n", udt->called.gt.nai);
  fprintf(stdout, "-- Address Information (digits): ");
  sccp_print_digits(udt->called.gt.digits, 6);

  fprintf(stdout, "\n");
  fprintf(stdout, "Calling Party Address: (%u bytes)\n", udt->calling_len);
  fprintf(stdout, "- Address Indicator:\n");
  fprintf(stdout, "-- Routing Indicator: 0x%02x\n", udt->calling.ai.routing_indicator);
  fprintf(stdout, "-- Global Title Indicator: 0x%02x\n", udt->calling.ai.global_title_indicator);
  fprintf(stdout, "-- SubsyStem Number Indicator: 0x%02x\n", udt->calling.ai.ssn_indicator);
  fprintf(stdout, "-- Point Code Indicator: 0x%02x\n", udt->calling.ai.point_code_indicator);
  fprintf(stdout, "- SubSystem Number: %u (0x%02x)\n", udt->calling.ssn, udt->calling.ssn);
  fprintf(stdout, "- Global Title:\n");
  fprintf(stdout, "-- Translation Type: 0x%02x\n", udt->calling.gt.translation_type);
  fprintf(stdout, "-- Numbering Plan: 0x%02x\n", udt->calling.gt.numbering_plan);
  fprintf(stdout, "-- Encoding Scheme: 0x%02x\n", udt->calling.gt.encoding_scheme);
  fprintf(stdout, "-- Nature of Address Indicator: 0x%02x\n", udt->calling.gt.nai);
  fprintf(stdout, "-- Address Information (digits): ");
  sccp_print_digits(udt->calling.gt.digits, 6);

  fprintf(stdout, "SCCP User Data: (%u bytes)\n", udt->data_len);
  hexdump(udt->data, udt->data_len);

#if 0
  fprintf(stdout, "Tag: 0x%04x (%hu)\n", tlv->tag, tlv->tag);
  fprintf(stdout, "Len: 0x%04x (%hu)\n", tlv->len, tlv->len);
  hexdump(tlv->val, tlv->len-4); /* -4 because len includes the tag-len fields */
#endif
}

void sccp_udt_free(sccp_data_udt_t *udt)
{
  if (udt) MYFREE(udt);
}


/*
 * sccp.h
 */
#ifndef _SCCP_H_
#define _SCCP_H_

#include <inttypes.h>
#include "defs.h"

/* Table 1/Q.713 - SCCP message types */
enum sccp_message_types {
  SCCP_MSG_TYPE_CR	= 1,
  SCCP_MSG_TYPE_CC	= 2,
  SCCP_MSG_TYPE_CREF	= 3,
  SCCP_MSG_TYPE_RLSD	= 4,
  SCCP_MSG_TYPE_RLC	= 5,
  SCCP_MSG_TYPE_DT1	= 6,
  SCCP_MSG_TYPE_DT2	= 7,
  SCCP_MSG_TYPE_AK	= 8,
  SCCP_MSG_TYPE_UDT	= 9,
  SCCP_MSG_TYPE_UDTS	= 10,
  SCCP_MSG_TYPE_ED	= 11,
  SCCP_MSG_TYPE_EA	= 12,
  SCCP_MSG_TYPE_RSR	= 13,
  SCCP_MSG_TYPE_RSC	= 14,
  SCCP_MSG_TYPE_ERR	= 15,
  SCCP_MSG_TYPE_IT	= 16,
  SCCP_MSG_TYPE_XUDT	= 17,
  SCCP_MSG_TYPE_XUDTS	= 18,
  SCCP_MSG_TYPE_LUDT	= 19,
  SCCP_MSG_TYPE_LUDTS	= 20
};

typedef struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint8_t point_code_indicator: 1,
	  ssn_indicator: 1,
	  global_title_indicator: 4,
	  routing_indicator: 1,
	  reserved: 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint8_t reserved: 1,
	  routing_indicator: 1,
	  global_title_indicator: 4,
	  ssn_indicator: 1,
	  point_code_indicator: 1;
#endif
} sccp_address_indicator_t;


/* how many pair of digits in GT (considering bcd) */
#define GT_DIGITS_SIZE		7
typedef struct {
  uint8_t translation_type;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint8_t encoding_scheme: 4;
  uint8_t numbering_plan: 4;
  uint8_t nai: 7; /* Nature of Address Indicator */
  uint8_t reserved: 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint8_t numbering_plan: 4;
  uint8_t encoding_scheme: 4;
  uint8_t reserved: 1;
  uint8_t nai: 7; /* Nature of Address Indicator */
#endif
  uint8_t digits[GT_DIGITS_SIZE];
} sccp_global_title_t;

/* Routing Indicator */
enum {
  SCCP_CALL_ROUTE_ON_GT			= 0,
  SCCP_CALL_ROUTE_ON_SSN		= 1
};

/* Global Title Indicator */
enum {
  SCCP_TITLE_IND_NONE			= 0,
  SCCP_TITLE_IND_NATURE_ONLY		= 1,
  SCCP_TITLE_IND_TRANSLATION_ONLY	= 2,
  SCCP_TITLE_IND_TRANS_NUM_ENC		= 3,
  SCCP_TITLE_IND_TRANS_NUM_ENC_NATURE	= 4
};


typedef struct {
  sccp_address_indicator_t ai; /* Address Indicator */
  uint8_t ssn; /* SubSystem Number (http://en.wikipedia.org/wiki/Subsystem_number) */
  sccp_global_title_t gt; /* Global Title */
} sccp_called_party_address_t;
typedef sccp_called_party_address_t sccp_calling_party_address_t;


typedef struct {
  /* mandantory */
  uint8_t mtype;
  uint8_t pclass: 4;
  uint8_t mhndl: 4;

  /* variable */
  uint8_t variable_called; /* pointer to the first mandatory variable parameter (called party addres) */
  uint8_t variable_calling; /* pointer to the second mandatory variable parameter (calling party address) */
  uint8_t variable_data; /* pointer to the third mandatory variable parameter (data) */

  uint8_t called_len;
  sccp_called_party_address_t called;
  uint8_t calling_len;
  sccp_calling_party_address_t calling;
  /* just need to fill up the following to reply back (tcap buffer) */
  uint8_t data_len;
  uint8_t data[SIGTRAN_MTU];
} sccp_data_udt_t;


/*
sccp_data_udt_t *sccp_build_udt(uint8_t pclass, uint8_t msg_handling,
    uint8_t variable_called, uint8_t variable_calling, uint8_t variable_data,
    sccp_called_party_address_t *called, sccp_calling_party_address_t *calling,
    octet *data, uint16_t datalen);
    */
sccp_data_udt_t *sccp_build_udt(uint8_t called_ssn, const char *called_gt,
    uint8_t calling_ssn, const char *calling_gt,
    octet *data, uint16_t datalen);

octet *sccp_udt2octet(sccp_data_udt_t *udt, uint32_t *nextpos);
sccp_data_udt_t *sccp_octet2udt(octet *buf, uint16_t buflen, uint32_t *nextpos);
void sccp_dump_udt(sccp_data_udt_t *udt);
void sccp_print_digits(uint8_t *digits, uint8_t len);
void sccp_udt_free(sccp_data_udt_t *udt);



#endif

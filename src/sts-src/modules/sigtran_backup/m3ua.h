/*
 * m3ua.h
 */
#ifndef _M3UA_H_
#define _M3UA_H_

#include "defs.h"
#include "llist.h"
#include "mytlv.h"

/*
 * ALL DATA IN M3UA MUST BE IN NETWORK BYTE ORDER (BIG ENDIAN)
 * #include <arpa/inet.h>
 * uint16_t var = htons();
 * uint32_t var = htonl();
 */

/* M3UA Common Message Header */
typedef struct {
  uint8_t version; /* Version (1) */
  uint8_t reserved; /* Reserved (0) */
  uint8_t mclass; /* Message Class */
  uint8_t mtype; /* Message Type */
  uint32_t mlen; /* Message Length */
} m3ua_head_t;

typedef struct {
  m3ua_head_t head;
  llist_t *tlvs; /* list of variable length parameters (TLV) */
} m3ua_t;

/* Message Classes and Types */
enum m3ua_msg_class {
  M3UA_MSG_CLASS_MGMT			= 0,
  M3UA_MSG_CLASS_TM			= 1,
  M3UA_MSG_CLASS_SSNM			= 2,
  M3UA_MSG_CLASS_ASPSM			= 3,
  M3UA_MSG_CLASS_ASPTM			= 4,
  M3UA_MSG_CLASS_RESERVED1		= 5,
  M3UA_MSG_CLASS_RESERVED2		= 6,
  M3UA_MSG_CLASS_RESERVED3		= 7,
  M3UA_MSG_CLASS_RESERVED4		= 8,
  M3UA_MSG_CLASS_RKM			= 9
};


/* Management Messages */
enum m3ua_msg_type_mgmt {
  M3UA_MSG_TYPE_MGMT_ERR		= 0,
  M3UA_MSG_TYPE_MGMT_NTFY		= 1
};

/* Transfer Messages */
enum m3ua_msg_type_tm {
  M3UA_MSG_TYPE_TM_RESERVED		= 0,
  M3UA_MSG_TYPE_TM_DATA			= 1
};

typedef uint32_t m3ua_point_code_t;
typedef struct {
  m3ua_point_code_t opc; /* originating point code */
  m3ua_point_code_t dpc; /* destination point code */
  uint8_t si; /* Service Indicator */
  uint8_t ni; /* Network Indicator */
  uint8_t mp; /* Message Priority */
  uint8_t sls; /* Signalling Link Selection */
  uint8_t data[SIGTRAN_MTU]; /* User Protocol Data (UDT) */
  uint16_t datalen; /* just calculated data (for ease of operations) */
} m3ua_protocol_data_t;

/* SS7 Signalling Network Management (SSNM) Messages */
enum m3ua_msg_type_ssnm {
  M3UA_MSG_TYPE_SSNM_RESERVED		= 0,
  M3UA_MSG_TYPE_SSNM_DUNA		= 1,
  M3UA_MSG_TYPE_SSNM_DAVA		= 2,
  M3UA_MSG_TYPE_SSNM_DAUD		= 3,
  M3UA_MSG_TYPE_SSNM_SCON		= 4,
  M3UA_MSG_TYPE_SSNM_DUPU		= 5,
  M3UA_MSG_TYPE_SSNM_DRST		= 6
};

/* ASP State Maintenance (ASPSM) Messages */
enum m3ua_msg_type_aspsm {
  M3UA_MSG_TYPE_ASPSM_RESERVED		= 0,
  M3UA_MSG_TYPE_ASPSM_ASPUP		= 1,
  M3UA_MSG_TYPE_ASPSM_ASPDN		= 2,
  M3UA_MSG_TYPE_ASPSM_BEAT		= 3,
  M3UA_MSG_TYPE_ASPSM_ASPUP_ACK		= 4,
  M3UA_MSG_TYPE_ASPSM_ASPDN_ACK		= 5,
  M3UA_MSG_TYPE_ASPSM_BEAT_ACK		= 6
};

/* ASP Traffic Maintenance (ASPTM) Messages */
enum m3ua_msg_type_asptm {
  M3UA_MSG_TYPE_ASPTM_RESERVED		= 0,
  M3UA_MSG_TYPE_ASPTM_ASPAC		= 1,
  M3UA_MSG_TYPE_ASPTM_ASPIA		= 2,
  M3UA_MSG_TYPE_ASPTM_ASPAC_ACK		= 3,
  M3UA_MSG_TYPE_ASPTM_ASPIA_ACK		= 4
};


/* Routing Key Management (RKM) Messages */
enum m3ua_msg_type_rkm {
  M3UA_MSG_TYPE_RKM_RESERVED		= 0,
  M3UA_MSG_TYPE_RKM_REG_REQ		= 1,
  M3UA_MSG_TYPE_RKM_REG_RSP		= 2,
  M3UA_MSG_TYPE_RKM_DEREG_REQ		= 3,
  M3UA_MSG_TYPE_RKM_DEREG_RSP		= 4
};

m3ua_t *m3ua_build(uint8_t mclass, uint8_t mtype, llist_t *tlvs);
octet *m3ua2octet(m3ua_t *m, uint32_t *nextpos);
m3ua_t *octet2m3ua(octet *buf, uint16_t buflen, uint32_t *nextpos);
void m3ua_dump(m3ua_t *m);
const char *m3ua_print_mclass(m3ua_t *m);
const char *m3ua_print_mtype(m3ua_t *m);
void m3ua_add_tlv(m3ua_t *m, mytlv_t *t);
void m3ua_free(m3ua_t *m);

m3ua_protocol_data_t *m3ua_octet2pdata(octet *buf, uint16_t buflen, uint32_t *nextpos);
octet *m3ua_pdata2octet(m3ua_protocol_data_t *pdata, uint32_t *nextpos);
void m3ua_pdata_dump(m3ua_protocol_data_t *pdata);

/* m3ua wrapper functions for the ease of development */
/* octed dynamically allocated, caller must free when possible */
octet *m3ua_octet_ASPUP(uint32_t *nextpos);
octet *m3ua_octet_ASPDN(uint32_t *nextpos);
octet *m3ua_octet_ASPAC(uint32_t *nextpos);
octet *m3ua_octet_ASPIA(uint32_t *nextpos);
octet *m3ua_octet_DAVA(uint32_t gwpc, uint32_t *nextpos); /* tell msc that point code is available */
octet *m3ua_octet_ASPSM_BEAT(uint32_t m3ua_hb, uint32_t *nextpos);




#endif

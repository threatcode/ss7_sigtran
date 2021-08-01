/*
 * tcap.h
 * ITU Q.773
 */
#ifndef _TCAP_H_
#define _TCAP_H_

#include "defs.h"
#include "llist.h"
#include "tlv.h"

#include <inttypes.h>

enum tcap_tag_type {
  TCAP_MSG_TYPE_UD		= 0x61,
  TCAP_MSG_TYPE_BEGIN		= 0x62,
  TCAP_MSG_TYPE_RESERVED1	= 0x63,
  TCAP_MSG_TYPE_END		= 0x64,
  TCAP_MSG_TYPE_CONTINUE	= 0x65,
  TCAP_MSG_TYPE_RESERVED2	= 0x66,
  TCAP_MSG_TYPE_ABORT		= 0x67,

  TCAP_TID_SRC			= 0x48,
  TCAP_TID_DST			= 0x49,
  TCAP_P_ABORT_CAUSE		= 0x4a,

  TCAP_DIALOG_PORTION_TAG	= 0x6b,
  TCAP_COMPONENT_PORTION_TAG	= 0x6c
};

enum tcap_component_type_tag {
  TCAP_CMP_TYPE_INVOKE			= 0xa1,
  TCAP_CMP_TYPE_RETURN_RESULT_LAST	= 0xa2,
  TCAP_CMP_TYPE_RETURN_ERROR		= 0xa3,
  TCAP_CMP_TYPE_REJECT			= 0xa4,
  TCAP_CMP_TYPE_RESERVED1		= 0xa5,
  TCAP_CMP_TYPE_RESERVED2		= 0xa6,
  TCAP_CMP_TYPE_RETURN_RESULT		= 0xa7
};

enum tcap_component_id_tag {
  TCAP_CMP_ID_INVOKE			= 0x02,
  TCAP_CMP_ID_LINKED			= 0x80
};

enum tcap_null_tag {
  TCAP_CMP_ID_NULL			= 0x05
};

enum tcap_constructor_tag {
  TCAP_CMP_TAG_CONSTRUCTOR		= 0x30
};

/* Operation Code Tag */
enum tcap_opcode_tag {
  TCAP_CMP_OPCODE_TAG_LOCAL		= 0x02,
  TCAP_CMP_OPCODE_TAG_GLOBAL		= 0x06
};

enum tcap_parameter_tag {
  TCAP_PARAM_TAG_SEQUENCE		= 0x30,
  TCAP_PARAM_TAG_SET			= 0x31
};

enum tcap_error_tag {
  TCAP_CMP_TAG_ERROR_LOCAL		= 0x02,
  TCAP_CMP_TAG_ERROR_GLOBAL		= 0x06
};

enum tcap_problem_code {
  TCAP_CMP_PROBLEM_GENERAL			= 0x80,
  TCAP_CMP_PROBLEM_INVOKE			= 0x81,
  TCAP_CMP_PROBLEM_RETURN_RESULT		= 0x82,
  TCAP_CMP_PROBLEM_RETURN_ERROR			= 0x83
};

enum tcap_problem_general_code {
  TCAP_CMP_PROBLEM_GENERAL_UNRECOGNIZED		= 0x00,
  TCAP_CMP_PROBLEM_GENERAL_MISTYPED		= 0x01,
  TCAP_CMP_PROBLEM_GEENRAL_BAD_STRUCTURE	= 0x02
};

enum tcap_problem_invoke_code {
  TCAP_CMP_PROBLEM_INVOKE_DUPLICATE_ID		= 0x00,
  TCAP_CMP_PROBLEM_INVOKE_UNRECOGNIZED_OP	= 0x01,
  TCAP_CMP_PROBLEM_INVOKE_MISTYPED_PARAM	= 0x02,
  TCAP_CMP_PROBLEM_INVOKE_RESOURCE_LIMIT	= 0x03,
  TCAP_CMP_PROBLEM_INVOKE_INITIATE_RELEASE	= 0x04,
  TCAP_CMP_PROBLEM_INVOKE_UNRECOGNIZED_LID	= 0x05, /* Unrecognized Linked ID */
  TCAP_CMP_PROBLEM_INVOKE_LRESPONSE_UNEXP	= 0x06, /* Linked Response Unexpected */
  TCAP_CMP_PROBLEM_INVOKE_UNEXP_LINKED_OP	= 0x07
};

enum tcap_problem_return_result_code {
  TCAP_CMP_PROBLEM_RETURN_RESULT_UNRECOGNIZED_INVOKE_ID		= 0x00,
  TCAP_CMP_PROBLEM_RETURN_RESULT_UNEXPECTED			= 0x01,
  TCAP_CMP_PROBLEM_RETURN_RESULT_MISTYPED			= 0x02
};

enum tcap_problem_return_error_code {
  TCAP_CMP_PROBLEM_RETURN_ERROR_UNRECOGNIZED_INVOKE_ID		= 0x00,
  TCAP_CMP_PROBLEM_RETURN_ERROR_RE_UNEXPECTED			= 0x01, /* Return Error Unexpected */
  TCAP_CMP_PROBLEM_RETURN_ERROR_UNRECOGNIZED			= 0x02,
  TCAP_CMP_PROBLEM_RETURN_ERROR_UNEXPECTED			= 0x03, /* Unexpected Error */
  TCAP_CMP_PROBLEM_RETURN_ERROR_MISTYPED			= 0x04
};


enum tcap_dialogue_portion {
  TCAP_DIALOG_EXTERNAL_TAG	= 0x28,
  TCAP_DIALOG_OID_TAG		= 0x06
};



typedef struct {
  uint8_t tag; /* tag (to distinguish between Originating (0x48) and Destination (0x49) transaction ID */
  uint8_t len;
  octet tid[4];
} tcap_tid_t;

/* dialogue portion tag */
typedef struct {
  uint8_t tag;
  uint8_t len;
  octet dlg_info[SIGTRAN_MTU];
} tcap_dlg_part_t;;

/* component portion tag */
typedef struct {
  uint8_t tag;
  uint8_t len;
  octet cmp_info[SIGTRAN_MTU];
} tcap_cmp_part_t;

/* component type (invoke, etc.) */
typedef struct {
  uint8_t type;
  uint8_t len;
  llist_t *tlvs;
} tcap_cmp_type_t;

typedef tcap_cmp_type_t tcap_cmp_invoke_t;
typedef tcap_cmp_type_t tcap_cmp_returnResultLast_t;
typedef tcap_cmp_type_t tcap_cmp_returnResult_t;
typedef tcap_cmp_type_t tcap_cmp_returnError_t;
typedef tcap_cmp_type_t tcap_cmp_reject_t;

/* dialogue portion broken down to parts */
typedef struct {
  uint8_t type;
  uint8_t len;
  llist_t *tlvs;
} tcap_dlg_type_t;


typedef struct {
  uint8_t mtype; /* TCAP Message Type */
  uint8_t mlen;
  tcap_tid_t src_tid; /* Mandatory */
  tcap_dlg_part_t *dlg_part;
  tcap_cmp_part_t *cmp_part;
} tcap_begin_msg_t;

typedef struct {
  uint8_t mtype; /* TCAP Message Type */
  uint8_t mlen;
  tcap_tid_t src_tid;
  tcap_tid_t dst_tid;
} tcap_continue_msg_t;

typedef struct {
  uint8_t mtype; /* TCAP Message Type */
  uint8_t mlen;
  tcap_tid_t dst_tid;
} tcap_end_msg_t;

typedef struct {
  uint8_t mtype; /* TCAP Message Type */
  uint8_t mlen;
  tcap_tid_t dst_tid;
} tcap_abort_msg_t;

tcap_begin_msg_t *tcap_build_begin(uint8_t mtype, uint8_t mlen, tcap_tid_t *src);
octet *tcap_begin2octet(tcap_begin_msg_t *t, uint16_t *nextpos);
tcap_begin_msg_t *octet2tcap_begin(octet *buf, uint16_t buflen, uint16_t *nextpos);
void tcap_dump_begin(tcap_begin_msg_t *t);

tcap_continue_msg_t *tcap_build_continue(uint8_t mtype, uint8_t mlen, tcap_tid_t *src);
octet *tcap_continue2octet(tcap_continue_msg_t *t, uint16_t *nextpos);
tcap_continue_msg_t *octet2tcap_continue(octet *buf, uint16_t buflen, uint16_t *nextpos);
void tcap_dump_continue(tcap_continue_msg_t *t);

tcap_end_msg_t *tcap_build_end(uint8_t mtype, uint8_t mlen, tcap_tid_t *src);
octet *tcap_end2octet(tcap_end_msg_t *t, uint16_t *nextpos);
tcap_end_msg_t *octet2tcap_end(octet *buf, uint16_t buflen, uint16_t *nextpos);
void tcap_dump_end(tcap_end_msg_t *t);

tcap_abort_msg_t *tcap_build_abort(uint8_t mtype, uint8_t mlen, tcap_tid_t *src);
octet *tcap_abort2octet(tcap_abort_msg_t *t, uint16_t *nextpos);
tcap_abort_msg_t *octet2tcap_abort(octet *buf, uint16_t buflen, uint16_t *nextpos);
void tcap_dump_abort(tcap_abort_msg_t *t);
uint8_t tcap_tag_is_constructor(uint8_t tag);

void tcap_free_begin(tcap_begin_msg_t *t);
void tcap_free_continue(tcap_continue_msg_t *t);
void tcap_free_end(tcap_end_msg_t *t);
void tcap_free_abort(tcap_abort_msg_t *t);

void tcap_free_begin(tcap_begin_msg_t *t);
void tcap_dlg_part_free(tcap_dlg_part_t *d);
void tcap_cmp_part_free(tcap_cmp_part_t *c);

tcap_cmp_type_t *tcap_cmp_part_parse(tcap_cmp_part_t *t);
void tcap_cmp_type_dump(tcap_cmp_type_t *ct);
void tcap_cmp_type_free(tcap_cmp_type_t *ct);

tcap_dlg_type_t *tcap_dlg_part_parse(tcap_dlg_part_t *t);
void tcap_dlg_type_dump(tcap_dlg_type_t *dt);
void tcap_dlg_type_free(tcap_dlg_type_t *dt);



#endif

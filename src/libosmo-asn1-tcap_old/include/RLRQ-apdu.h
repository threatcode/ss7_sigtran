/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "DialoguePDUs"
 * 	found in "../asn/DialoguePDUs.asn"
 */

#ifndef	_RLRQ_apdu_H_
#define	_RLRQ_apdu_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Release-request-reason.h"
#include <EXTERNAL.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RLRQ-apdu */
typedef struct RLRQ_apdu {
	Release_request_reason_t	*reason	/* OPTIONAL */;
	struct user_information {
		A_SEQUENCE_OF(EXTERNAL_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *user_information;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RLRQ_apdu_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RLRQ_apdu;

#ifdef __cplusplus
}
#endif

#endif	/* _RLRQ_apdu_H_ */

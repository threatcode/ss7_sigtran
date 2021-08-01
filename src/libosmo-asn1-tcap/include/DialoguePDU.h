/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "DialoguePDUs"
 * 	found in "../asn/DialoguePDUs.asn"
 */

#ifndef	_DialoguePDU_H_
#define	_DialoguePDU_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AARQ-apdu.h"
#include "AARE-apdu.h"
#include "ABRT-apdu.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DialoguePDU_PR {
	DialoguePDU_PR_NOTHING,	/* No components present */
	DialoguePDU_PR_dialogueRequest,
	DialoguePDU_PR_dialogueResponse,
	DialoguePDU_PR_dialogueAbort
} DialoguePDU_PR;

/* DialoguePDU */
typedef struct DialoguePDU {
	DialoguePDU_PR present;
	union DialoguePDU_u {
		AARQ_apdu_t	 dialogueRequest;
		AARE_apdu_t	 dialogueResponse;
		ABRT_apdu_t	 dialogueAbort;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DialoguePDU_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DialoguePDU;

#ifdef __cplusplus
}
#endif

#endif	/* _DialoguePDU_H_ */

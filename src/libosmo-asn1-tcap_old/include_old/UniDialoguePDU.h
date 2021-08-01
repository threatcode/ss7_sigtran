/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "UnidialoguePDUs"
 * 	found in "../asn/UnidialoguePDUs.asn"
 */

#ifndef	_UniDialoguePDU_H_
#define	_UniDialoguePDU_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AUDT-apdu.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UniDialoguePDU_PR {
	UniDialoguePDU_PR_NOTHING,	/* No components present */
	UniDialoguePDU_PR_unidialoguePDU
} UniDialoguePDU_PR;

/* UniDialoguePDU */
typedef struct UniDialoguePDU {
	UniDialoguePDU_PR present;
	union UniDialoguePDU_u {
		AUDT_apdu_t	 unidialoguePDU;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UniDialoguePDU_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UniDialoguePDU;

#ifdef __cplusplus
}
#endif

#endif	/* _UniDialoguePDU_H_ */

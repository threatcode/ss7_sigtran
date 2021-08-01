/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "TCAPMessages"
 * 	found in "../asn/tcap.asn"
 */

#ifndef	_Unidirectional_H_
#define	_Unidirectional_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ComponentPortion.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ExternalPDU;

/* Unidirectional */
typedef struct Unidirectional {
	struct ExternalPDU	*dialoguePortion	/* OPTIONAL */;
	ComponentPortion_t	 components;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Unidirectional_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Unidirectional;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "DialoguePortion.h"

#endif	/* _Unidirectional_H_ */

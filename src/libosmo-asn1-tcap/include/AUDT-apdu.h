/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "UnidialoguePDUs"
 * 	found in "../asn/UnidialoguePDUs.asn"
 */

#ifndef	_AUDT_apdu_H_
#define	_AUDT_apdu_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>
#include <OBJECT_IDENTIFIER.h>
#include <EXTERNAL.h>
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum protocol_version {
	protocol_version_version1	= 0
} e_protocol_version;

/* AUDT-apdu */
typedef struct AUDT_apdu {
	BIT_STRING_t	*protocol_version	/* DEFAULT {version1} */;
	OBJECT_IDENTIFIER_t	 application_context_name;
	struct user_information {
		A_SEQUENCE_OF(EXTERNAL_t) list;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *user_information;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AUDT_apdu_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AUDT_apdu;

#ifdef __cplusplus
}
#endif

#endif	/* _AUDT_apdu_H_ */

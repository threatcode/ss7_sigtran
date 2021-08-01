/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "TCAPMessages"
 * 	found in "../asn/tcap.asn"
 */

#ifndef	_Invoke_H_
#define	_Invoke_H_


#include <asn_application.h>

/* Including external dependencies */
#include "InvokeIdType.h"
#include "OPERATION.h"
#include "Parameter.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Invoke */
typedef struct Invoke {
	InvokeIdType_t	 invokeID;
	InvokeIdType_t	*linkedID	/* OPTIONAL */;
	OPERATION_t	 opCode;
	Parameter_t	*parameter	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Invoke_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Invoke;

#ifdef __cplusplus
}
#endif

#endif	/* _Invoke_H_ */

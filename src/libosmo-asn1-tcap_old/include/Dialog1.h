/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "TCAPMessages"
 * 	found in "../asn/tcap.asn"
 */

#ifndef	_Dialog1_H_
#define	_Dialog1_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dialog1 */
typedef OCTET_STRING_t	 Dialog1_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Dialog1;
asn_struct_free_f Dialog1_free;
asn_struct_print_f Dialog1_print;
asn_constr_check_f Dialog1_constraint;
ber_type_decoder_f Dialog1_decode_ber;
der_type_encoder_f Dialog1_encode_der;
xer_type_decoder_f Dialog1_decode_xer;
xer_type_encoder_f Dialog1_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _Dialog1_H_ */

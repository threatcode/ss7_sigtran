/*
 * Generated by asn1c-0.9.22 (http://lionet.info/asn1c)
 * From ASN.1 module "TCAPMessages"
 * 	found in "../asn/tcap.asn"
 */

#include <asn_internal.h>

#include "ExternalPDU.h"

static asn_TYPE_member_t asn_MBR_ExternalPDU_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ExternalPDU, oid),
		(ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
		0,
		&asn_DEF_OBJECT_IDENTIFIER,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"oid"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ExternalPDU, dialog),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_DialoguePDU,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"dialog"
		},
};
static ber_tlv_tag_t asn_DEF_ExternalPDU_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (8 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_ExternalPDU_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 }, /* oid at 18 */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 1, 0, 0 } /* dialog at 20 */
};
static asn_SEQUENCE_specifics_t asn_SPC_ExternalPDU_specs_1 = {
	sizeof(struct ExternalPDU),
	offsetof(struct ExternalPDU, _asn_ctx),
	asn_MAP_ExternalPDU_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_ExternalPDU = {
	"ExternalPDU",
	"ExternalPDU",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_ExternalPDU_tags_1,
	sizeof(asn_DEF_ExternalPDU_tags_1)
		/sizeof(asn_DEF_ExternalPDU_tags_1[0]) - 1, /* 1 */
	asn_DEF_ExternalPDU_tags_1,	/* Same as above */
	sizeof(asn_DEF_ExternalPDU_tags_1)
		/sizeof(asn_DEF_ExternalPDU_tags_1[0]), /* 2 */
	0,	/* No PER visible constraints */
	asn_MBR_ExternalPDU_1,
	2,	/* Elements count */
	&asn_SPC_ExternalPDU_specs_1	/* Additional specs */
};


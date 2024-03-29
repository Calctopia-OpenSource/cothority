/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "LDSSecurityObject"
 * 	found in "efsod.asn1"
 */

#include "LDSSecurityObject.h"

static int
memb_dataGroupHashValues_constraint_1(asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 2 && size <= 16)) {
		/* Perform validation of the inner elements */
		return td->check_constraints(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_TYPE_member_t asn_MBR_dataGroupHashValues_4[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_DataGroupHash,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		""
		},
};
static const ber_tlv_tag_t asn_DEF_dataGroupHashValues_tags_4[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_dataGroupHashValues_specs_4 = {
	sizeof(struct dataGroupHashValues),
	offsetof(struct dataGroupHashValues, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_dataGroupHashValues_4 = {
	"dataGroupHashValues",
	"dataGroupHashValues",
	SEQUENCE_OF_free,
	SEQUENCE_OF_print,
	SEQUENCE_OF_constraint,
	SEQUENCE_OF_decode_ber,
	SEQUENCE_OF_encode_der,
	SEQUENCE_OF_decode_xer,
	SEQUENCE_OF_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_dataGroupHashValues_tags_4,
	sizeof(asn_DEF_dataGroupHashValues_tags_4)
		/sizeof(asn_DEF_dataGroupHashValues_tags_4[0]), /* 1 */
	asn_DEF_dataGroupHashValues_tags_4,	/* Same as above */
	sizeof(asn_DEF_dataGroupHashValues_tags_4)
		/sizeof(asn_DEF_dataGroupHashValues_tags_4[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_dataGroupHashValues_4,
	1,	/* Single element */
	&asn_SPC_dataGroupHashValues_specs_4	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_LDSSecurityObject_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct LDSSecurityObject, version),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_LDSSecurityObjectVersion,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"version"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LDSSecurityObject, hashAlgorithm),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_DigestAlgorithmIdentifier,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"hashAlgorithm"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LDSSecurityObject, dataGroupHashValues),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_dataGroupHashValues_4,
		memb_dataGroupHashValues_constraint_1,
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"dataGroupHashValues"
		},
};
static const ber_tlv_tag_t asn_DEF_LDSSecurityObject_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LDSSecurityObject_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 1 }, /* hashAlgorithm */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -1, 0 } /* dataGroupHashValues */
};
static asn_SEQUENCE_specifics_t asn_SPC_LDSSecurityObject_specs_1 = {
	sizeof(struct LDSSecurityObject),
	offsetof(struct LDSSecurityObject, _asn_ctx),
	asn_MAP_LDSSecurityObject_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_LDSSecurityObject = {
	"LDSSecurityObject",
	"LDSSecurityObject",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_LDSSecurityObject_tags_1,
	sizeof(asn_DEF_LDSSecurityObject_tags_1)
		/sizeof(asn_DEF_LDSSecurityObject_tags_1[0]), /* 1 */
	asn_DEF_LDSSecurityObject_tags_1,	/* Same as above */
	sizeof(asn_DEF_LDSSecurityObject_tags_1)
		/sizeof(asn_DEF_LDSSecurityObject_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_LDSSecurityObject_1,
	3,	/* Elements count */
	&asn_SPC_LDSSecurityObject_specs_1	/* Additional specs */
};


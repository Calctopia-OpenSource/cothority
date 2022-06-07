#include "icao.h"

#define printe printf

char *ossl_err_as_string (void)
{ BIO *bio = BIO_new (BIO_s_mem ());
  ERR_print_errors (bio);
  char *buf = NULL;
  size_t len = BIO_get_mem_data (bio, &buf);
  char *ret = (char *) calloc (1, 1 + len);
  if (ret)
     memcpy (ret, buf, len);
  BIO_free (bio);
  return ret;
}

unsigned char* print_arcs(OBJECT_IDENTIFIER_t *oid) {
#define MAX_LENGTH_OID 100
             unsigned long fixed_arcs[10];   // Try with fixed space first
             unsigned long *arcs = fixed_arcs;
             int arc_type_size = sizeof(fixed_arcs[0]);      // sizeof(long)
             int arc_slots = sizeof(fixed_arcs)/sizeof(fixed_arcs[0]); // 10
             int count;      // Real number of arcs.
             int i, len;
	     unsigned char *ret = (unsigned char *) malloc(MAX_LENGTH_OID);;
	     ret[0] = '\0';

	     count = OBJECT_IDENTIFIER_get_arcs(oid, arcs,
	             arc_type_size, arc_slots);	
	     if(count > arc_slots) {
		     arc_slots = count;
		     arcs = (unsigned long*) malloc(arc_type_size * arc_slots);
		     if(!arcs) return NULL;
		     count = OBJECT_IDENTIFIER_get_arcs(oid, arcs,
			     arc_type_size, arc_slots);
		     assert(count == arc_slots);
	     }

	     len = 0;
	     for(i = 0; i < count; i++) {
		     len += snprintf((char*) ret+len, MAX_LENGTH_OID, "%d.", (int) arcs[i]);
             }
	     ret[len-1] = '\0';
	     if(arcs != fixed_arcs) free(arcs);

	     return ret;
}

int check_ICAO(unsigned char *pBuffer, int nBufferSize, unsigned char *dg11, int dg11Size, unsigned char *dg1, int dg1Size, // INPUT
		unsigned char *ID, int ID_len, unsigned char *expiration, unsigned char *name) // OUTPUT
{
    BIO *in = NULL, *cont = NULL, *in2 = NULL, *in3 = NULL, *outLDSSO = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    PKCS7 *p7 = NULL;
    X509_LOOKUP *lookup;
    STACK_OF(X509) *dscCerts;
    X509* dscCertificate;
    X509_NAME *issuerName;
    int ret = 1;
    int lastpos = -1;
    int i, j;
    long length;
    unsigned char* personalNumber = NULL; int hasPersonalNumber = 0;
    unsigned char documentNumber[10]; int hasDocumentNumber = 0;
    unsigned char expirationDate[7];
    unsigned char nameHolder[40];
    unsigned char* countryCode = NULL;
    unsigned char* ldsso = NULL;
    int dg1HashOK = 0, dg11HashOK = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    /* Set up trusted CA certificate store */
    st = X509_STORE_new();
    lookup=X509_STORE_add_lookup(st,X509_LOOKUP_ICAO());
    if (lookup == NULL)
        goto err;

    in = BIO_new(BIO_s_mem());
    BIO_write(in, pBuffer, nBufferSize);
    if (!in)
        goto err;

    p7 = d2i_PKCS7_bio(in, NULL);
    if (!p7)
        goto err;

    if (!PKCS7_type_is_signed(p7)) {
        PKCS7err(PKCS7_F_PKCS7_GET0_SIGNERS, PKCS7_R_WRONG_CONTENT_TYPE);
        goto err;
    }

    outLDSSO = BIO_new(BIO_s_mem());
    if (!PKCS7_verify(p7, NULL, st, NULL, outLDSSO, 0)) {
        printe("Verification Failure");
        goto err;
    }

    // Hash(DG11) must equal the hash contained on the LDSSecurityObject
    if (outLDSSO == NULL) {
        printe("Couldn't obtain to LDSSecurityObject");
        goto err;
    }
    length = BIO_get_mem_data(outLDSSO, &ldsso);
    if (length > 0) {
	LDSSecurityObject_t *lds = NULL;
	unsigned char md_value_DG11[EVP_MAX_MD_SIZE], md_value_DG1[EVP_MAX_MD_SIZE];
	unsigned int md_len_DG11 = 0, md_len_DG1 = 0;

	lds = (LDSSecurityObject_t*)calloc(1, sizeof *lds);
        asn_dec_rval_t rval = ber_decode(0,&asn_DEF_LDSSecurityObject,(void**)&lds,ldsso,length);
	if(rval.code != RC_OK) {
            printe("Couldn't decode LDSSecurityObject");
	    goto err;
	}

	// obtain OID of the hash algorithm used on the LDSSecurityObject
	unsigned char* txtobj = print_arcs(&lds->hashAlgorithm.algorithm);
	ASN1_OBJECT *obj = OBJ_txt2obj((const char*) txtobj, 1);

	// Calculate hashes of DG1 and DG11
	if (dg11Size > 8) {
	    EVP_MD_CTX *mdcDig = EVP_MD_CTX_create();
	    EVP_DigestInit_ex(mdcDig, EVP_get_digestbynid(OBJ_obj2nid(obj)), NULL);
	    EVP_DigestUpdate(mdcDig, dg11, dg11Size-1);
	    EVP_DigestFinal_ex(mdcDig, md_value_DG11, &md_len_DG11);
	    EVP_MD_CTX_cleanup(mdcDig);
	}
        if (dg1Size >= 75) {
            EVP_MD_CTX *mdcDig = EVP_MD_CTX_create();
	    EVP_DigestInit_ex(mdcDig, EVP_get_digestbynid(OBJ_obj2nid(obj)), NULL);
	    EVP_DigestUpdate(mdcDig, dg1, dg1Size-1);
	    EVP_DigestFinal_ex(mdcDig, md_value_DG1, &md_len_DG1);
	    EVP_MD_CTX_cleanup(mdcDig);
        }
	free(txtobj);

	// compare hashes of user's DG11 with LDSSecurityObject's DG11
	for(i=0;i<lds->dataGroupHashValues.list.count;i++) {
            DataGroupHash_t *dgh=lds->dataGroupHashValues.list.array[i];
	    if (dgh->dataGroupNumber == 11 && dg11Size > 8) {
		if (strncmp((const char*)dgh->dataGroupHashValue.buf, (const char*)md_value_DG11, md_len_DG11) != 0) {
			printe("Recomputed hash for DG11 differs from LDSSecurityObject");
			free(lds);
			goto err;
		}
		 else dg11HashOK = 1;
	    }
            if (dgh->dataGroupNumber == 1 && dg1Size >= 75) {
                if (strncmp((const char*)dgh->dataGroupHashValue.buf, (const char*)md_value_DG1, md_len_DG1) != 0) {
                        printe("Recomputed hash for DG1 differs from LDSSecurityObject");
                        free(lds);
		        goto err;
	        }
		 else dg1HashOK = 1;
            }
        }
	free(lds);
    } else {
	printe("LDSSecurityObject isn't long enough");
        goto err;
    }

    // DG11 must start with 0x6b, contain 0x5f10 two times, then next byte is the length
    // of the field that contains the personal number
    if (dg11Size > 8) {
        if (dg11[0] == 0x6b) {
            char* pos = NULL; 
	    char sstr[3]; sstr[0] = 0x5f; sstr[1] = 0x10; sstr[2] = '\0';
            pos = strstr( (const char*) dg11, (const char*) sstr);
	    if (pos != NULL) {
                pos = strstr(pos+2, (const char*) sstr);
		if (pos != NULL) {
                    int length = *(pos+2);
		    personalNumber = (unsigned char*)malloc(length+1);
                    memcpy(personalNumber, (pos+3), length);
		    personalNumber[length] = '\0';
		    hasPersonalNumber = 1;
		}
	    }
	}
    }

    // DG1 must start with 0x61 and contain 0x5f1f one time, then the next byte is the length of the TDX size,
    //  where for X = (1,2,3) the length is (90, 72, 88), then, the document number is at position (11, 42, 50)
    //  the date of expiry is at position (44, 63, 71) and the name is at position (66, 11, 11)
    if (dg1Size >= 75) {
        if (dg1[0] == 0x61 && dg1[2] == 0x5f && dg1[3] == 0x1f) {
            if (dg1[4] == 90) { // TD1
                memcpy(documentNumber, (const void*) &dg1[10], 9);
                documentNumber[9] = '\0';
		memcpy(expirationDate, (const void*) &dg1[43], 6);
                expirationDate[6] = '\0';
		memcpy(nameHolder, (const void*) &dg1[65], 30);
                nameHolder[30] = '\0';
		hasDocumentNumber = 1;
	    } else if (dg1[4] == 72) { // TD2
                memcpy(documentNumber, (const void*) &dg1[41], 9);
                documentNumber[9] = '\0';
		memcpy(expirationDate, (const void*) &dg1[62], 6);
                expirationDate[6] = '\0';
		memcpy(nameHolder, (const void*) &dg1[10], 31);
                nameHolder[31] = '\0';
		hasDocumentNumber = 1;
	    } else if (dg1[4] == 88) { // TD3
                memcpy(documentNumber, (const void*) &dg1[49], 9);
		documentNumber[9] = '\0';
		memcpy(expirationDate, (const void*) &dg1[70], 6);
                expirationDate[6] = '\0';
		memcpy(nameHolder, (const void*) &dg1[10], 39);
                nameHolder[39] = '\0';
		hasDocumentNumber = 1;
	    }
	}
    }
    
    // Extract country from DSC certificate
    dscCerts = p7->d.sign->cert;
    if (sk_X509_num(dscCerts) > 0) {
        dscCertificate = sk_X509_value(dscCerts, 0);
    } else {
        printe("Doesn't contain DSC certificate");
	goto err;
    }
    issuerName = X509_get_issuer_name(dscCertificate);
    for (;;) {
	lastpos = X509_NAME_get_index_by_NID(issuerName, NID_countryName, lastpos);
	if (lastpos == -1)
	    break;
	X509_NAME_ENTRY *e = X509_NAME_get_entry(issuerName, lastpos);
	ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
	countryCode = ASN1_STRING_data(d);
    }

    if (countryCode == NULL) {
        printe("Couln't extract countryCode from DSC certificate");
	goto err;
    }

    // Compose miner's unique ID
    if (!dg1HashOK && !dg11HashOK) {
        printe("User must provide at least one valid EF_DG1 or EF_G11");
	goto err;
    } else if (!dg1HashOK && dg11HashOK && !hasDocumentNumber) {
        printe("User must provide a valid EF_DG11 containing a Document Number, or an EF_DG1");
	goto err;
    }

    // Preference of DG11's Personal Number over DG1's Document Number:
    //  DG1's Document Number only acceptable if DG11 doesn't contain a Personal Number
    if (dg11HashOK && hasPersonalNumber) {
        strncat((char*)ID, (const char*) countryCode, strlen((const char*) countryCode));
	strncat((char*)ID, "-", 1);
	strncat((char*)ID, (const char*) personalNumber, strlen((const char*)personalNumber));
	strncat((char*)expiration, (const char*) expirationDate, 7);
	strncat((char*)name, (const char*) nameHolder, 40);
    } else if ((dg1HashOK && hasDocumentNumber) && (dg11HashOK && !hasPersonalNumber) ) {
        strncat((char*)ID, (const char*) countryCode, strlen((const char*) countryCode));
        strncat((char*)ID, "-", 1);
        strncat((char*)ID, (const char*) documentNumber, strlen((const char*)documentNumber));
	strncat((char*)expiration, (const char*) expirationDate, 7);
	strncat((char*)name, (const char*) nameHolder, 40);
    } else {
	printe("Provide valid EF_DG11 containing Personal Number, or valid EF_DG1");
        goto err;
    }

    // Everything calculated OK
    ret = 0;

 err:

    if (ret) {
	printe("Error Verifying Data");
	unsigned long luerr = ERR_get_error();
	printe("[%lu](%s)", luerr, ERR_error_string(luerr, NULL));
	printe("Error is: %s", ERR_reason_error_string(luerr));
	char *error = ossl_err_as_string();
	printe("%s", error);
	free(error);
    }

    if (p7)
        PKCS7_free(p7);
    if (cacert)
        X509_free(cacert);

    if (in)
        BIO_free(in);
    if (in2)
        BIO_free(in2);
    if (in3)
	BIO_free(in3);
    if (outLDSSO)
	BIO_free(outLDSSO);
    
    if (personalNumber)
	free(personalNumber);

    return ret;
}

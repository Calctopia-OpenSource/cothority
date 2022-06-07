#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <by_ICAO.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "LDSSecurityObject.h"

int check_ICAO(unsigned char* pBuffer, int nBufferSize, unsigned char* dg11, int dg11Size, unsigned char* dg1, int dg1Size, unsigned char* ID, int ID_len, unsigned char* expiration, unsigned char* name);

#endif

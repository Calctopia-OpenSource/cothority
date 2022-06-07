/* File:   by_buffer.h */

#ifndef BY_ICAO_H
#define BY_ICAO_H

#include <openssl/x509.h>

#ifdef    __cplusplus
extern "C" {
#endif
	X509_LOOKUP_METHOD *X509_LOOKUP_ICAO(void);
#ifdef    __cplusplus
}
#endif

#endif    /* BY_ICAO_H */

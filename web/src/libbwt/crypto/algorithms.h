#ifndef ALGORITHMS_H
#define ALGORITHMS_H

#include <stddef.h>

typedef enum {
    HS256,
    HS384,
    HS512
} AlgorithmHMAC;

typedef enum {
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512
} AlgorithmPEM;

int openssl_sign_sha_hmac(AlgorithmHMAC alg_id,
                          unsigned char** result, size_t* result_size,
                          const unsigned char* data, size_t data_size,
                          const unsigned char* key, int key_size);

bool openssl_verify_sha_hmac(AlgorithmHMAC alg_id,
                             const unsigned char* signature, size_t signature_size,
                             const unsigned char* data, size_t data_size,
                             const unsigned char* key, int key_size);

int openssl_sign_sha_pem(AlgorithmPEM alg_id,
                         unsigned char** result, size_t* result_size,
                         const unsigned char* data, size_t data_size,
                         const unsigned char* key, size_t key_size);

bool openssl_verify_sha_pem(AlgorithmPEM alg_id,
                            const unsigned char* signature, size_t signature_size,
                            const unsigned char* data, size_t data_size,
                            const unsigned char* key, size_t key_size);

#endif //ALGORITHMS_H

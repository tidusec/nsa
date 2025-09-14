#include "bwt_sign.h"

#include "algorithms.h"

#include <limits.h>
#include <stdlib.h>

void sign_none(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size) {

    *result_size = 0;

    // Even though probably not needed, set result to a valid buffer to avoid undefined behaviour
    *result = malloc(1);
}

void sign_hs256(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    if (key_size > INT_MAX) {
        *result = nullptr;
        *result_size = 0;
    } else {
        openssl_sign_sha_hmac(HS256, result, result_size, data, data_size, key, (int) key_size);
    }
}

void sign_hs384(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    if (key_size > INT_MAX) {
        *result = nullptr;
        *result_size = 0;
    } else {
        openssl_sign_sha_hmac(HS384, result, result_size, data, data_size, key, (int) key_size);
    }
}

void sign_hs512(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    if (key_size > INT_MAX) {
        *result = nullptr;
        *result_size = 0;
    } else {
        openssl_sign_sha_hmac(HS512, result, result_size, data, data_size, key, (int) key_size);
    }
}



void sign_rs256(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(RS256, result, result_size, data, data_size, key, key_size);
}

void sign_rs384(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(RS384, result, result_size, data, data_size, key, key_size);
}

void sign_rs512(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(RS512, result, result_size, data, data_size, key, key_size);
}

void sign_es256(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(ES256, result, result_size, data, data_size, key, key_size);
}

void sign_es384(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(ES384, result, result_size, data, data_size, key, key_size);
}

void sign_es512(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(ES512, result, result_size, data, data_size, key, key_size);
}

void sign_ps256(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(PS256, result, result_size, data, data_size, key, key_size);
}

void sign_ps384(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(PS384, result, result_size, data, data_size, key, key_size);
}

void sign_ps512(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    openssl_sign_sha_pem(PS512, result, result_size, data, data_size, key, key_size);
}

const signing_function SIGNING_FUNCTIONS[] = {
    //    sign_none,
    sign_hs256,
    sign_hs384,
    sign_hs512,
    sign_rs256,
    sign_rs384,
    sign_rs512,
    sign_es256,
    sign_es384,
    sign_es512,
    sign_ps256,
    sign_ps384,
    sign_ps512
};
const size_t SIGNING_FUNCTIONS_SIZE = sizeof(SIGNING_FUNCTIONS) / sizeof(SIGNING_FUNCTIONS[0]);
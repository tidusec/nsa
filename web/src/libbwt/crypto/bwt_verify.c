#include "bwt_verify.h"

#include "algorithms.h"

#include <limits.h>

bool verify_none(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return true;
}

bool verify_hs256(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    if (key_size > INT_MAX) {
        return false;
    } else {
        return openssl_verify_sha_hmac(HS256, signature, signature_size, data, data_size, key, (int) key_size);
    }
}

bool verify_hs384(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    if (key_size > INT_MAX) {
        return false;
    } else {
        return openssl_verify_sha_hmac(HS384, signature, signature_size, data, data_size, key, (int) key_size);
    }
}

bool verify_hs512(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    if (key_size > INT_MAX) {
        return false;
    } else {
        return openssl_verify_sha_hmac(HS512, signature, signature_size, data, data_size, key, (int) key_size);
    }
}

bool verify_rs256(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(RS256, signature, signature_size, data, data_size, key, key_size);
}

bool verify_rs384(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(RS384, signature, signature_size, data, data_size, key, key_size);
}

bool verify_rs512(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(RS512, signature, signature_size, data, data_size, key, key_size);
}

bool verify_es256(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(ES256, signature, signature_size, data, data_size, key, key_size);
}

bool verify_es384(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(ES384, signature, signature_size, data, data_size, key, key_size);
}

bool verify_es512(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(ES512, signature, signature_size, data, data_size, key, key_size);
}

bool verify_ps256(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(PS256, signature, signature_size, data, data_size, key, key_size);
}

bool verify_ps384(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(PS384, signature, signature_size, data, data_size, key, key_size);
}

bool verify_ps512(
    const unsigned char* signature, const size_t signature_size,
    const unsigned char* data, const size_t data_size,
    const unsigned char* key, const size_t key_size) {

    return openssl_verify_sha_pem(PS512, signature, signature_size, data, data_size, key, key_size);
}

const verification_function VERIFICATION_FUNCTIONS[] = {
    //    verify_none,
    verify_hs256,
    verify_hs384,
    verify_hs512,
    verify_rs256,
    verify_rs384,
    verify_rs512,
    verify_es256,
    verify_es384,
    verify_es512,
    verify_ps256,
    verify_ps384,
    verify_ps512,
};
const size_t VERIFICATION_FUNCTIONS_SIZE = sizeof(VERIFICATION_FUNCTIONS) / sizeof(VERIFICATION_FUNCTIONS[0]);
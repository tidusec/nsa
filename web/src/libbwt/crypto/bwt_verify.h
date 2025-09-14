#ifndef BWT_VERIFY_H
#define BWT_VERIFY_H

#include <stddef.h>

typedef bool (*verification_function)(
    const unsigned char*, size_t,
    const unsigned char*, size_t,
    const unsigned char*, size_t);

bool verify_none(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_hs256(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_hs384(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_hs512(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_rs256(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_rs384(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_rs512(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_es256(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_es384(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_es512(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_ps256(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_ps384(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

bool verify_ps512(
    const unsigned char* signature, size_t signature_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

extern const verification_function VERIFICATION_FUNCTIONS[];
extern const size_t VERIFICATION_FUNCTIONS_SIZE;

#endif //BWT_VERIFY_H

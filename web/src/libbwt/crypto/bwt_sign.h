#ifndef BWT_SIGN_H
#define BWT_SIGN_H

#include <stddef.h>

typedef void (*signing_function)(
    unsigned char**, size_t*,
    const unsigned char*, size_t,
    const unsigned char*, size_t);

void sign_none(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_hs256(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_hs384(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_hs512(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_rs256(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_rs384(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_rs512(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_es256(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_es384(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_es512(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_ps256(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_ps384(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

void sign_ps512(
    unsigned char** result, size_t* result_size,
    const unsigned char* data, size_t data_size,
    const unsigned char* key, size_t key_size);

extern const signing_function SIGNING_FUNCTIONS[];
extern const size_t SIGNING_FUNCTIONS_SIZE;

#endif //BWT_SIGN_H

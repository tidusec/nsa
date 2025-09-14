#ifndef B64_URLENCODE_H
#define B64_URLENCODE_H

#include <stddef.h>

char* b64_url_encode(const unsigned char *src, size_t len);

unsigned char* b64_url_decode(const char *src, size_t len);

unsigned char* b64_url_decode_ex(const char *src, size_t len, size_t *out_len);

#endif //B64_URLENCODE_H

#include "b64_urlsafe.h"

#include "b64.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>


static inline void b64_urlsafe_to_b64(const char* src, const size_t len, char** dest, size_t* dest_len) {
	const size_t n_padding = 4 - (len % 4);
	*dest_len = len + n_padding;
	*dest = calloc(*dest_len, sizeof(char));
	strncpy(*dest, src, *dest_len);

	char* cpy = *dest;
	for (size_t i = 0; cpy[i] != '\0'; i++)
	{
		if (cpy[i] == '-')
		{
			cpy[i] = '+';
		}
		else if (cpy[i] == '_')
		{
			cpy[i] = '/';
		}
	}
}

static inline void b64_to_b64_urlsafe(char* enc) {
	for (size_t i = 0; enc[i] != '\0'; i++)
	{
		if (enc[i] == '+')
		{
			enc[i] = '-';
		}
		else if (enc[i] == '/')
		{
			enc[i] = '_';
		}
		else if (enc[i] == '=')
		{
			enc[i] = '\0';
		}
	}
}


char* b64_url_encode(const unsigned char* src, const size_t len) {
	char* enc = b64_encode(src, len);

	b64_to_b64_urlsafe(enc);

	return enc;
}

unsigned char* b64_url_decode(const char* src, const size_t len) {
	return b64_url_decode_ex(src, len, nullptr);
}

unsigned char* b64_url_decode_ex(const char* src, const size_t len, size_t* out_len) {
	size_t src_cpy_len;
	char* src_cpy;
	b64_urlsafe_to_b64(src, len, &src_cpy, &src_cpy_len);

	unsigned char* dec = b64_decode_ex(src_cpy, src_cpy_len, out_len);

	free(src_cpy);
	return dec;
}


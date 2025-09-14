#include "libbwt.h"

#include "b64/b64_urlsafe.h"

#include "crypto/bwt_sign.h"
#include "crypto/bwt_verify.h"

#include "sizeof_utils.h"

#include <stdlib.h>
#include <string.h>

// Compute how much memory is needed to store the (encoded) payload
static inline size_t get_payload_size(const bwt_entry_t* entries, const size_t entry_size) {
    size_t size = 0;
    for (size_t i = 0; i < entry_size; ++i) {
        const bwt_entry_t* entry = &entries[i];
        size += entry->key.size + entry->value.size + 2;
    }
    return size;
}

static inline int get_entries_size(size_t* result, const char* payload, const size_t payload_size) {
    *result = 0;

    // Count occurrences of PAYLOAD_SEP. occurrences/2 is the entries array size.
    for (size_t i = 0; i < payload_size; ++i) {
        switch (payload[i]) {
            case PAYLOAD_SEPARATOR:
                (*result)++;
                break;
            case '\0':
                // WTF!? This should not happen. Abort the function.
                return -1;
            default: break;
        }
    }

    // Count of PAYLOAD_SEP must be divisible by two
    if (*result % 2 != 0) {
        return -2;
    }

    *result /= 2;
    return 0;
}

static inline size_t get_entry_size(const char* position) {
    size_t size = 0;

    while (*position != PAYLOAD_SEPARATOR) {
        ++size;
        ++position;
    }

    return size;
}

static inline void entries_free(bwt_entry_t* entries, const size_t entry_size) {
    for (size_t i = 0; i < entry_size; ++i) {
        free(entries->key.data);
        free(entries->value.data);
        entries->key.data = nullptr;
        entries->value.data = nullptr;
    }
}

static inline bool entries_all_valid(const bwt_entry_t* entries, const size_t entry_size) {
    for (size_t i = 0; i < entry_size; ++i) {
        if (entries->key.data == nullptr || entries->value.data == nullptr) {
            return false;
        }
    }
    return true;
}

static inline void create_payload(char* result, const bwt_entry_t* entries, const size_t entry_size) {
    // Track current position in the result buffer
    char* pos = result;

    // Convert every entry into "key${PAYLOAD_SEPARATOR}value${PAYLOAD_SEPARATOR}" and append it to the result
    for (size_t i = 0; i < entry_size; ++i) {
        // Extract the current entry
        const bwt_entry_t* entry = &entries[i];

        // Copy the key and append PAYLOAD_SEPARATOR
        strcpy(pos, entry->key.data);
        pos += entry->key.size;
        *pos = PAYLOAD_SEPARATOR;
        pos++;

        // Copy the value and append PAYLOAD_SEPARATOR
        strcpy(pos, entry->value.data);
        pos += entry->value.size;
        *pos = PAYLOAD_SEPARATOR;
        pos++;
    }
}

static inline int decode_payload(bwt_entry_t** result, size_t* result_size,
                                 const char* payload, const size_t payload_size) {
    *result = nullptr;

    // Handle special case
    if (payload_size == 0) {
        *result_size = 0;
        return 0;
    }

    // Get count_of_PAYLOAD_SEP/2, which is the amount of entries stored
    if (get_entries_size(result_size, payload, payload_size) != 0) {
        goto abort_error;
    }

    // Ensure payload ends with PAYLOAD_SEP
    // Important to avoid buffer overread with get_entry_size
    if (payload[payload_size - 1] != PAYLOAD_SEPARATOR) {
        goto abort_error;
    }

    // Allocate buffer for the entries
    *result = malloc(*result_size * sizeof(bwt_entry_t));
    if (*result == nullptr) {
        goto abort_error;
    }

    // bwt_entry_t has just two bwt_string_t members and the loop is guaranteed to run an even number of times
    // (since the number of PAYLOAD_SEP is even).
    // Also for every two loop iterations, the first one sets the key and the second one the value.
    // So this works to parse all key-value pairs in the payload
    bwt_string_t* pos = (bwt_string_t*) *result;
    for (size_t i = 0; i < payload_size; ++i) {
        pos->size = get_entry_size(payload + i);
        pos->data = strndup(payload + i, pos->size);
        i += pos->size;
        pos++;
    }

    // Perform check for strndup nullptr afterwards because it is easier to code this way
    // (Here all bwt_string_t::data members are guaranteed to be allocated or null)
    if (!entries_all_valid(*result, *result_size)) {
        entries_free(*result, *result_size);
        goto abort_error;
    }

    return 0;

abort_error:
    free(*result);
    *result = nullptr;
    *result_size = 0;
    return -1;
}

char* create_bwt(const AlgorithmID algorithm,
                 const bwt_entry_t* entries, const size_t entries_size,
                 const unsigned char* key, const size_t key_size) {
    size_t signature_size;
    unsigned char* signature = nullptr;
    char* result = nullptr;

    // Compute the memory requirements for the encoded payload
    const size_t payload_size = get_payload_size(entries, entries_size);

    // header + PART_SET + payload + PART_SEP
    const size_t data_size = HEADER_SIZE + 1 + payload_size + 1;

    // Allocate memory for the token data (which is then signed)
    unsigned char* data = malloc(data_size);
    if (data == nullptr) {
        goto create_bwt_done;
    }

    // Set magic bytes
    memcpy(data, MAGIC_BYTES, sizeof(MAGIC_BYTES));

    // Set header value 6 (algorithm)
    data[sizeof(MAGIC_BYTES)] = ~algorithm;

    // Set header value 7 (type)
    data[sizeof(MAGIC_BYTES)+1] = ~BWT;

    // Set separator for header and payload
    data[HEADER_SIZE] = PART_SEPARATOR;

    // Set payload
    create_payload((char*) data + HEADER_SIZE + 1, entries, entries_size);

    // Set separator for payload and signature
    data[HEADER_SIZE + 1 + payload_size] = PART_SEPARATOR;

    const unsigned char index = algorithm;
    if (index >= SIGNING_FUNCTIONS_SIZE) {
        goto create_bwt_done;
    }

    // Sign the data blob
    SIGNING_FUNCTIONS[index](&signature, &signature_size, data, data_size, key, key_size);

    // Signing the data blob failed, abort
    if (signature == nullptr) {
        goto create_bwt_done;
    }

    // Try to allocate space to append the signature to the end of the data blob
    unsigned char* tmp = realloc(data, data_size + signature_size);
    if (tmp == nullptr) {
        goto create_bwt_done;
    }
    data = tmp;

    // Copy signature to the end of data
    memcpy(data + data_size, signature, signature_size);

    //b64_urlencode the final token
    result = b64_url_encode(data, data_size + signature_size);

create_bwt_done:
    free(data);
    free(signature);
    return result;
}

bool verify_bwt(const AlgorithmID algorithm, const char* token, const unsigned char* key, const size_t key_size) {
    bwt_t* bwt = parse_bwt(algorithm, token, key, key_size);

    if (bwt == nullptr) {
        return false;
    }

    free_bwt(bwt);
    return true;
}

bwt_t* parse_bwt(const AlgorithmID algorithm, const char* token, const unsigned char* key, const size_t key_size) {
    bwt_t* bwt = malloc(sizeof(bwt_t));
    bwt_t* result = nullptr;

    // Decode token
    size_t decoded_size;
    unsigned char* token_dec = b64_url_decode_ex(token, strlen(token), &decoded_size);
    if (token_dec == nullptr) {
        goto verify_bwt_done;  // Quit if decoding fails
    }

    // The smallest token possible consists of the header, a separator, an empty payload, another separator
    // and an empty signature. So the smallest possible size is header + PART_SEP + PART_SEP.
    constexpr size_t smallest_token_size = HEADER_SIZE + 1 + 1;

    // If the token is smaller than the smallest possible size it is guaranteed to be invalid and we can safely quit
    if (decoded_size < smallest_token_size) {
        goto verify_bwt_done;
    }

    // Check if the token begins with our magic bytes
    if (memcmp(token_dec, MAGIC_BYTES, sizeof(MAGIC_BYTES)) != 0) {
        goto verify_bwt_done;
    }

    // First six header bytes are magic bytes, then the algorithm id follows
    const AlgorithmID token_alg = (unsigned char) ~token_dec[sizeof(MAGIC_BYTES)];
    if (token_alg != algorithm) {
        goto verify_bwt_done;  // Algorithm mismatch, abort
    }

    const TypeID token_type = (unsigned char) ~token_dec[sizeof(MAGIC_BYTES)+1];
    if (token_type != BWT) {
        goto verify_bwt_done;  // Invalid token type
    }

    // Find payload by advancing to the first PART_SEPARATOR
    const unsigned char* payload = memchr(token_dec, PART_SEPARATOR, decoded_size);
    // If PART_SEP is not found or is the last character (prevent buffer-overread), abort
    if (payload == nullptr || payload == token_dec + decoded_size - 1) {
        goto verify_bwt_done;  // Quit if it was not found
    }
    payload++;  // Skip PART_SEPARATOR so that payload points to the beginning of the payload

    // Find signature by advancing to the second PART_SEPARATOR
    const unsigned char* signature = memchr(payload, PART_SEPARATOR, decoded_size);
    // If PART_SEP is not found or is the last character (empty signatures are currently not supported), abort
    if (signature == nullptr || signature == token_dec + decoded_size - 1) {
        goto verify_bwt_done;  // Quit if it was not found
    }
    signature++;  // Skip PART_SEPARATOR so that signature points to the beginning of the signature

    // The size of the data is signature - beginning_of_token (so the bytes from beginning to signature)
    const size_t data_size = signature - token_dec;
    // The size of the signature is the size_of_overall_token - data (so the bytes from signature to the end)
    // == (token_dec + decoded_size) - signature
    const size_t signature_size = decoded_size - data_size;
    // The bytes from the payload start to the signature (excluding final PART_SEP)
    const size_t payload_size = signature - payload - 1;

    // Ensure the header fits into bwt_t::raw_header
    const char* header = (char*) token_dec;
    if (strlen(header) > sizeof_member(bwt_t, raw_header)) {
        goto verify_bwt_done;
    }

    // First set easy values
    bwt->algorithm = token_alg;
    bwt->type = token_type;
    bwt->signature_size = signature_size;

    // Then the more complicated ones
    strcpy(bwt->raw_header, header);

    // And the ones which allocate memory at the end
    bwt->raw_payload = strdup((const char*) payload);
    if (bwt->raw_payload == nullptr) {
        goto verify_bwt_done;
    }
    bwt->signature = malloc(signature_size);
    if (bwt->signature == nullptr) {
        free(bwt->raw_payload);
        goto verify_bwt_done;
    }
    memcpy(bwt->signature, signature, signature_size);
    if (decode_payload(&bwt->entries, &bwt->entries_size, bwt->raw_payload, payload_size) != 0) {
        free(bwt->raw_payload);
        free(bwt->signature);
        goto verify_bwt_done;
    }

    // Verify signature using the given algorithm
    const unsigned char index = bwt->algorithm;
    if (index >= VERIFICATION_FUNCTIONS_SIZE
        || !VERIFICATION_FUNCTIONS[index](signature, signature_size, token_dec, data_size, key, key_size)) {
        free_bwt(bwt);
    } else {
        result = bwt;
    }

    bwt = nullptr;

verify_bwt_done:
    free(token_dec);
    free(bwt);
    return result;
}

void free_bwt(bwt_t* bwt) {
    free(bwt->raw_payload);
    free(bwt->signature);
    entries_free(bwt->entries, bwt->entries_size);
    free(bwt);
}
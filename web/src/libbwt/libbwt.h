#ifndef LIBBWT_H
#define LIBBWT_H

#include <stddef.h>

constexpr char MAGIC_BYTES[] = { '\x01', 'B', 'W', 'T', '\x13', '\x37' };
constexpr char MAGIC_BYTES_B64[] = { 'A', 'U', 'J', 'X', 'V', 'B', 'M', '3' };

// Header is magic bytes, algorithm byte and type byte
constexpr size_t HEADER_SIZE = sizeof(MAGIC_BYTES) + 2;

constexpr char PART_SEPARATOR = '\x00';

constexpr char PAYLOAD_SEPARATOR = '\x03';

typedef enum : unsigned char {
    //    NONE = 0,
    HS256 = 0,
    HS384 = 1,
    HS512 = 2,
    RS256 = 3,
    RS384 = 4,
    RS512 = 5,
    ES256 = 6,
    ES384 = 7,
    ES512 = 8,
    PS256 = 9,
    PS384 = 10,
    PS512 = 11
} AlgorithmID;

typedef enum : unsigned char {
    BWT = 0,
} TypeID;

typedef struct {
    char* data;   // A UTF-8 encoded NULL-terminated string
    size_t size;  // The size of the string (EXCLUDING the terminating NULL byte)
} bwt_string_t;

typedef struct {
    bwt_string_t key;
    bwt_string_t value;
} bwt_entry_t;

typedef struct {
    char raw_header[HEADER_SIZE + 1];  // The raw (NULL-terminated) header (can be empty)
    AlgorithmID algorithm;             // The algorithm to use
    TypeID type;                       // The type
    char* raw_payload;                 // The raw (NULL-terminated) payload (can be empty).
    bwt_entry_t* entries;              // An array of the stored key-value pairs
    size_t entries_size;               // The length of the entries array
    unsigned char* signature;          // The signature
    size_t signature_size;             // The size of the signature
} bwt_t;

// Create and encoded BWT from the given entries and the given key
char* create_bwt(AlgorithmID algorithm,
                 const bwt_entry_t* entries, size_t entries_size,
                 const unsigned char* key, size_t key_size);

// Return true if the given encoded token is a valid BWT signed with the given key using the given algorithm
bool verify_bwt(AlgorithmID algorithm, const char* token, const unsigned char* key, size_t key_size);

// Decode the given encoded token into a bwt struct. Return a valid bwt_t struct on success or NULL on failure
// Also checks the signature using the given algorithm. If it is invalid, the function fails (returns NULL).
bwt_t* parse_bwt(AlgorithmID algorithm, const char* token, const unsigned char* key, size_t key_size);

// Free a bwt_t struct including all entries, the raw payload, etc
void free_bwt(bwt_t* bwt);

#endif //LIBBWT_H

# Binary Web Tokens (BWT)

Binary Web Tokens are a lightweight alternative to [JSON Web Tokens](https://jwt.io/) (JWT). They are simpler, more secure, more compact, use less space and are faster to create and verify.

## The format
A BWT consists of three parts, the header, the payload and the signature. Between header and payload and payload and signature are separator characters called `PART_SEPARATOR`. The header and the payload may not contain any `PART_SEPARATOR` characters. The signature has no such restriction. The token is base64URL encoded.

### Header
The header is 8 byte long and consists of 6 magic bytes, followed by one byte specifying the algorithm and one byte specifying the type.

The following table showcases the structure (table header is byte offset):

|   0    |   1    |   2    |   3    |   4    |   5    |   6   |   7    |
| :----: | :----: | :----: | :----: | :----: | :----: | :---: | :----: |
| `0x01` | `0x42` | `0x57` | `0x54` | `0x13` | `0x37` | `ALG` | `TYPE` |

**Magic Bytes**:
 - `\x01BWT\x13\x37`
 - Since base64 encodes 3 source bytes to 4 destination bytes, the magic bytes will always be encoded to "`AUJXVBM3`", making a BWT easily recognizable even in encoded form.

**Algorithm**:
 - `0xff`: HS256
 - `0xfe`: HS384
 - `0xfd`: HS512
 - `0xfc`: RS256
 - `0xfb`: RS384
 - `0xfa`: RS512
 - `0xf9`: ES256
 - `0xf8`: ES384
 - `0xf7`: ES512
 - `0xf6`: PS256
 - `0xf5`: PS384
 - `0xf4`: PS512

**Type**:
 - `0xff`: BWT

### Payload
The payload consists of arbitrarily many key-value pairs. The key and the value must be UTF-8 encoded strings and end with `PAYLOAD_SEPARATOR` characters. Thus they may not contain PAYLOAD_SEPARATOR characters. There is no way to store arrays or dictionaries as values. However if this is needed one might serialize the array/dictionary into a string and store it like this. Or alternatively one might encode them as `key_0`, `key_1`, ... for arrays or as `key_subkey`, `key_othersubkey` for dictionaries.

### Signature
Everything after the second `PART_SEPARATOR` up until the end of the token is considered to be the signature. Thus there are no restrictions as to what characters may appear here. For the signature, everything up to and including the second `PART_SEPARATOR` character (Header, `PART_SEPARATOR`, Payload, `PART_SEPARATOR`) is signed with the algorithm specified in the header using a given key.

### Special characters
 - `PART_SEPARATOR`: `0x00`
 - `PAYLOAD_SEPARATOR`: `0x03`

## Security
BWTs have been developed with security in mind. Thus:
 - there is no insecure NONE algorithm
 - they are as simple as possible
 - every operation of every implementation should force the developer to specify the used algorithm and verify if it matches the one in the token to avoid [Algorithm confusion attacks](https://portswigger.net/web-security/jwt/algorithm-confusion).

# PyBWT
PyBWT is a Python wrapper for the BWT library `libbwt.so`, which is written in C for the sake of efficiency.

## Installation

Install with **pip**:

```
$ pip install PyBWT
```

## Usage
```
>>> import bwt
>>> encoded = bwt.encode({"some": "payload"}, "secret", algorithm="HS256")
>>> print(encoded)
AUJXVBM3__8Ac29tZQNwYXlsb2FkAwAOp__UBxRJlqHSNQTSt7lUhk1zh2D8sG2Dt3OkHSfoYg
>>> bwt.decode(encoded, "secret", algorithm="HS256")
{'some': 'payload'}
```
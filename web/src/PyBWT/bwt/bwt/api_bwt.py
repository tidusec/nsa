import ctypes

from .api_ctypes import libbwt, bwt_entry_t, bwt_string_t

ALGORITHMS = [
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512"
]

_DEFAULT_ENCODING = "utf-8"
_PAYLOAD_ENCODING = "utf-8"
_RAW_TOKEN_ENCODING = "utf-8"

_ALGORITHM_MAPPING = {k: v for v, k in enumerate(ALGORITHMS)}


def encode(payload: dict, key, algorithm: str, encoding: str = _DEFAULT_ENCODING) -> str | None:
    """Encodes a given dictionary into a BWT signed with the given key. Note that all type information of the keys and
    values is lost as they are all converted into strings.

    :param payload: The data to decode.
    :type payload: dict
    :param key: The key to use to sign the token.
    :type key: str | bytes
    :param algorithm: The algorithm to use for signing.
    :type algorithm: str
    :param encoding: The encoding used to encode the token and key (if they are not already encoded). Defaults to utf-8.
    :type encoding: str
    :returns: A signed BWT containing the payload.
    :rtype: dict | None
"""

    if not isinstance(key, bytes):
        key = key.encode(encoding)

    entries_size = len(payload)
    payload_entries = (bwt_entry_t * entries_size)()
    i = 0
    for payload_key, value in payload.items():
        if not isinstance(payload_key, bytes):
            payload_key = str(payload_key).encode(_PAYLOAD_ENCODING)

        if not isinstance(value, bytes):
            value = str(value).encode(_PAYLOAD_ENCODING)

        payload_entries[i] = bwt_entry_t(
            key = bwt_string_t(payload_key, len(payload_key)),
            value = bwt_string_t(value, len(value))
        )
        i += 1

    token = libbwt.create_bwt(_ALGORITHM_MAPPING[algorithm], payload_entries, entries_size, key, len(key))

    if not token:
        return None

    return token.decode(_RAW_TOKEN_ENCODING)

def decode(token: str | bytes, key: str | bytes, algorithm: str, encoding: str = _DEFAULT_ENCODING) -> dict | None:
    """Decodes (and validates) the given token using the given algorithm and key. Validation includes verification of
    the signature.

    :param token: The (encoded) token to decode.
    :type token: str | bytes
    :param key: The key to use for verification.
    :type key: str | bytes
    :param algorithm: The algorithm to use for signature verification.
    :type algorithm: str
    :param encoding: The encoding used to encode the token and key (if they are not already encoded). Defaults to utf-8.
    :type encoding: str
    :returns: None if the token is invalid, a dictionary containing the token contents otherwise.
    :rtype: dict | None
    """
    if not isinstance(key, bytes):
        key = key.encode(encoding)

    if not isinstance(token, bytes):
        token = token.encode(encoding)

    algorithm = algorithm.upper()

    bwt_ptr = libbwt.parse_bwt(_ALGORITHM_MAPPING[algorithm], token, key, len(key))

    if not bwt_ptr:
        return None

    result = {}
    bwt = bwt_ptr.contents

    for i in range(0, bwt.entries_size):
        entry = bwt.entries[i]
        result[entry.key.data.decode(_PAYLOAD_ENCODING)] = entry.value.data.decode(_PAYLOAD_ENCODING)

    libbwt.free_bwt(bwt_ptr)

    return result

def verify(token: str | bytes, key: str | bytes, algorithm: str, encoding: str = _DEFAULT_ENCODING) -> bool:
    """Verifies the given token using the given algorithm and key.

    :param token: The (encoded) token to verify.
    :type token: str | bytes
    :param key: The key to use for verification.
    :type key: str | bytes
    :param algorithm: The algorithm to use for signature verification.
    :type algorithm: str
    :param encoding: The encoding used to encode the token and key (if they are not already encoded). Defaults to utf-8.
    :type encoding: str
    :returns: True if the token is valid, False otherwise.
    :rtype: bool
    """

    if not isinstance(key, bytes):
        key = key.encode(encoding)

    if not isinstance(token, bytes):
        token = token.encode(encoding)

    algorithm = algorithm.upper()

    return libbwt.verify_bwt(_ALGORITHM_MAPPING[algorithm], token, key, len(key))
from .api_bwt import encode, decode, verify, ALGORITHMS

__version__ = "0.1.1"

__title__ = "PyBWT"
__description__ = "Binary Web Token implementation in Python"

__author__ = "nullptr"

__license__ = "AGPLv3"


__all__ = [
    ALGORITHMS,
    encode,
    decode,
    verify
]

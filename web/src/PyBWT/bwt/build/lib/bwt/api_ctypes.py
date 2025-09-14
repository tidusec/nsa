import ctypes
import os

_LIB_FILE = "libbwt.so"
_CURRENT_PATH = os.path.dirname(os.path.realpath(__file__))
_LIB_PATH = os.path.join(_CURRENT_PATH, _LIB_FILE)

_ALG_TYPE = ctypes.c_ubyte
_SIG_TYPE = ctypes.c_char_p


libbwt = None


class bwt_string_t(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_char_p),
        ("size", ctypes.c_size_t),
    ]


class bwt_entry_t(ctypes.Structure):
    _fields_ = [
        ("key", bwt_string_t),
        ("value", bwt_string_t),
    ]


class bwt_t(ctypes.Structure):
    _fields_ = [
        ("raw_header", ctypes.c_char * 9),
        ("algorithm", _ALG_TYPE),
        ("type", ctypes.c_ubyte),
        ("raw_payload", ctypes.c_char_p),
        ("entries", ctypes.POINTER(bwt_entry_t)),
        ("entries_size", ctypes.c_size_t),
        ("signature", _SIG_TYPE),
        ("signature_size", ctypes.c_size_t),
    ]


def setup():
    global libbwt
    libbwt = ctypes.cdll.LoadLibrary(_LIB_PATH)

    libbwt.create_bwt.argtypes = [_ALG_TYPE, ctypes.POINTER(bwt_entry_t), ctypes.c_size_t, _SIG_TYPE, ctypes.c_size_t]
    libbwt.create_bwt.restype = ctypes.c_char_p

    libbwt.verify_bwt.argtypes = [_ALG_TYPE, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    libbwt.verify_bwt.restype = ctypes.c_bool

    libbwt.parse_bwt.argtypes = [_ALG_TYPE, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    libbwt.parse_bwt.restype = ctypes.POINTER(bwt_t)

    libbwt.free_bwt.argtypes = [ctypes.POINTER(bwt_t)]
    libbwt.free_bwt.restype = None

setup()
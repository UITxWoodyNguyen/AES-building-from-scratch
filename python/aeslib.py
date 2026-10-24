"""
aeslib.py - Python ctypes wrapper for AES and modes of operation.

Wraps the pure C API defined in include/aes_c_api.h.
Zero external build dependencies (uses ctypes from standard library).
"""

import os
import sys
import ctypes
from ctypes import c_int, c_char_p, c_size_t, POINTER, c_uint8, c_void_p
from typing import Optional, Tuple, Union

# ============================================================
#  Status / Error codes (from aes_c_api.h)
# ============================================================
AES_STATUS_OK                 =  0
AES_STATUS_ERR_INVALID_KEY   = -1
AES_STATUS_ERR_INVALID_IV    = -2
AES_STATUS_ERR_INVALID_INPUT = -3
AES_STATUS_ERR_AUTH_FAILED   = -4
AES_STATUS_ERR_INVALID_TAG   = -5
AES_STATUS_ERR_INVALID_NONCE = -6
AES_STATUS_ERR_INVALID_PARAM = -7
AES_STATUS_ERR_BUFFER_SMALL  = -8
AES_STATUS_ERR_NULL_PTR      = -9


class AESError(Exception):
    """Base exception for AES operations."""
    def __init__(self, code: int, message: str = ""):
        self.code = code
        super().__init__(message or f"AES operation failed with error code {code}")


class AuthenticationError(AESError):
    """Raised when authentication tag verification fails."""
    pass


class InvalidKeyError(AESError):
    """Raised when key is invalid."""
    pass


class InvalidParamError(AESError):
    """Raised when a parameter is invalid."""
    pass


def _map_error(code: int, msg: str = ""):
    if code == AES_STATUS_ERR_AUTH_FAILED:
        return AuthenticationError(code, msg)
    if code == AES_STATUS_ERR_INVALID_KEY:
        return InvalidKeyError(code, msg)
    if code in (AES_STATUS_ERR_INVALID_IV, AES_STATUS_ERR_INVALID_NONCE,
                AES_STATUS_ERR_INVALID_TAG, AES_STATUS_ERR_INVALID_PARAM,
                AES_STATUS_ERR_INVALID_INPUT):
        return InvalidParamError(code, msg)
    return AESError(code, msg)


# ============================================================
#  Library Loader
# ============================================================
def _find_library() -> str:
    """Find aes_shared library across platforms and build directories."""
    # 1. Environment variable
    env_path = os.environ.get("AES_LIB_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    # Candidate filenames
    if sys.platform == "win32":
        filenames = ["aes_shared.dll", "libaes_shared.dll"]
    elif sys.platform == "darwin":
        filenames = ["libaes_shared.dylib", "aes_shared.dylib"]
    else:
        filenames = ["libaes_shared.so", "aes_shared.so"]

    # Search directories
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    search_dirs = [
        os.path.join(repo_root, "Build_gcc"),
        os.path.join(repo_root, "Build_clang"),
        os.path.join(repo_root, "Build_msvc", "Release"),
        os.path.join(repo_root, "Build_msvc", "Debug"),
        os.path.join(repo_root, "build"),
        os.path.join(repo_root, "dist"),
        os.path.dirname(__file__),
    ]

    for d in search_dirs:
        for fn in filenames:
            cand = os.path.join(d, fn)
            if os.path.isfile(cand):
                return cand

    raise FileNotFoundError(
        f"Cannot find AES shared library ({filenames[0]}). "
        f"Please build the project first or set the AES_LIB_PATH environment variable."
    )


def _load_library() -> ctypes.CDLL:
    lib_path = _find_library()

    # On Windows with MinGW DLL, add MSYS2 mingw64/bin to DLL search path if available
    if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
        mingw_bin = r"C:\msys64\mingw64\bin"
        if os.path.isdir(mingw_bin):
            try:
                os.add_dll_directory(mingw_bin)
            except OSError:
                pass
        lib_dir = os.path.dirname(lib_path)
        if os.path.isdir(lib_dir):
            try:
                os.add_dll_directory(lib_dir)
            except OSError:
                pass

    return ctypes.CDLL(lib_path)


_lib = _load_library()

# Setup C function signatures
_lib.aes_version.restype = c_char_p
_lib.aes_version.argtypes = []

_lib.aes_error_string.restype = c_char_p
_lib.aes_error_string.argtypes = [c_int]

_lib.aes_ctx_new.restype = c_void_p
_lib.aes_ctx_new.argtypes = []

_lib.aes_ctx_init.restype = c_int
_lib.aes_ctx_init.argtypes = [c_void_p, POINTER(c_uint8), c_int]

_lib.aes_ctx_free.restype = None
_lib.aes_ctx_free.argtypes = [c_void_p]

_lib.aes_encrypt_block.restype = c_int
_lib.aes_encrypt_block.argtypes = [c_void_p, POINTER(c_uint8), POINTER(c_uint8)]

_lib.aes_decrypt_block.restype = c_int
_lib.aes_decrypt_block.argtypes = [c_void_p, POINTER(c_uint8), POINTER(c_uint8)]

# Modes
_lib.aes_ecb_encrypt.restype = c_int
_lib.aes_ecb_encrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_ecb_decrypt.restype = c_int
_lib.aes_ecb_decrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_cbc_encrypt.restype = c_int
_lib.aes_cbc_encrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_cbc_decrypt.restype = c_int
_lib.aes_cbc_decrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_cfb_encrypt.restype = c_int
_lib.aes_cfb_encrypt.argtypes = [POINTER(c_uint8), c_int, c_int, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_cfb_decrypt.restype = c_int
_lib.aes_cfb_decrypt.argtypes = [POINTER(c_uint8), c_int, c_int, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_ofb_encrypt.restype = c_int
_lib.aes_ofb_encrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_ofb_decrypt.restype = c_int
_lib.aes_ofb_decrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_ctr_crypt.restype = c_int
_lib.aes_ctr_crypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_ccm_encrypt.restype = c_int
_lib.aes_ccm_encrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), c_size_t,
                                  POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t,
                                  POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_ccm_decrypt.restype = c_int
_lib.aes_ccm_decrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), c_size_t,
                                  POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t,
                                  POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_gcm_encrypt.restype = c_int
_lib.aes_gcm_encrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), c_size_t,
                                  POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t,
                                  POINTER(c_uint8), POINTER(c_uint8), c_size_t]

_lib.aes_gcm_decrypt.restype = c_int
_lib.aes_gcm_decrypt.argtypes = [POINTER(c_uint8), c_int, POINTER(c_uint8), c_size_t,
                                  POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t,
                                  POINTER(c_uint8), POINTER(c_uint8), c_size_t]


# Helper to convert bytes-like object to uint8 pointer
def _to_u8_ptr(data: Union[bytes, bytearray, None]):
    if data is None:
        return None
    return (c_uint8 * len(data)).from_buffer_copy(data)


def _check_rc(rc: int):
    if rc != AES_STATUS_OK:
        msg = _lib.aes_error_string(rc).decode("utf-8", errors="replace")
        raise _map_error(rc, msg)


def version() -> str:
    """Return AES Suite library version."""
    return _lib.aes_version().decode("utf-8")


def _validate_key(key: bytes) -> int:
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Invalid AES key length: {len(key)} bytes. Expected 16, 24, or 32.")
    return len(key) * 8


# ============================================================
#  High-level Python API
# ============================================================

def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    key_bits = _validate_key(key)
    if len(plaintext) % 16 != 0:
        raise ValueError("Plaintext length must be a multiple of 16 bytes for ECB mode without padding.")
    out = bytearray(len(plaintext))
    rc = _lib.aes_ecb_encrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(plaintext),
                              (c_uint8 * len(out)).from_buffer(out), len(plaintext))
    _check_rc(rc)
    return bytes(out)


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    key_bits = _validate_key(key)
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes for ECB mode.")
    out = bytearray(len(ciphertext))
    rc = _lib.aes_ecb_decrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(ciphertext),
                              (c_uint8 * len(out)).from_buffer(out), len(ciphertext))
    _check_rc(rc)
    return bytes(out)


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    key_bits = _validate_key(key)
    if len(iv) != 16:
        raise ValueError("CBC mode requires a 16-byte IV.")
    if len(plaintext) % 16 != 0:
        raise ValueError("Plaintext length must be a multiple of 16 bytes for CBC mode without padding.")
    out = bytearray(len(plaintext))
    rc = _lib.aes_cbc_encrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(iv),
                              _to_u8_ptr(plaintext), (c_uint8 * len(out)).from_buffer(out), len(plaintext))
    _check_rc(rc)
    return bytes(out)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    key_bits = _validate_key(key)
    if len(iv) != 16:
        raise ValueError("CBC mode requires a 16-byte IV.")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes for CBC mode.")
    out = bytearray(len(ciphertext))
    rc = _lib.aes_cbc_decrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(iv),
                              _to_u8_ptr(ciphertext), (c_uint8 * len(out)).from_buffer(out), len(ciphertext))
    _check_rc(rc)
    return bytes(out)


def cfb_encrypt(key: bytes, iv: bytes, plaintext: bytes, segment_bits: int = 128) -> bytes:
    key_bits = _validate_key(key)
    if len(iv) != 16:
        raise ValueError("CFB mode requires a 16-byte IV.")
    out = bytearray(len(plaintext))
    rc = _lib.aes_cfb_encrypt(_to_u8_ptr(key), key_bits, segment_bits, _to_u8_ptr(iv),
                              _to_u8_ptr(plaintext), (c_uint8 * len(out)).from_buffer(out), len(plaintext))
    _check_rc(rc)
    return bytes(out)


def cfb_decrypt(key: bytes, iv: bytes, ciphertext: bytes, segment_bits: int = 128) -> bytes:
    key_bits = _validate_key(key)
    if len(iv) != 16:
        raise ValueError("CFB mode requires a 16-byte IV.")
    out = bytearray(len(ciphertext))
    rc = _lib.aes_cfb_decrypt(_to_u8_ptr(key), key_bits, segment_bits, _to_u8_ptr(iv),
                              _to_u8_ptr(ciphertext), (c_uint8 * len(out)).from_buffer(out), len(ciphertext))
    _check_rc(rc)
    return bytes(out)


def ofb_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    key_bits = _validate_key(key)
    if len(iv) != 16:
        raise ValueError("OFB mode requires a 16-byte IV.")
    if len(plaintext) % 16 != 0:
        raise ValueError("Plaintext length must be a multiple of 16 bytes for OFB mode.")
    out = bytearray(len(plaintext))
    rc = _lib.aes_ofb_encrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(iv),
                              _to_u8_ptr(plaintext), (c_uint8 * len(out)).from_buffer(out), len(plaintext))
    _check_rc(rc)
    return bytes(out)


def ofb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return ofb_encrypt(key, iv, ciphertext)


def ctr_crypt(key: bytes, counter: bytes, data: bytes) -> bytes:
    key_bits = _validate_key(key)
    if len(counter) != 16:
        raise ValueError("CTR mode requires a 16-byte initial counter.")
    out = bytearray(len(data))
    rc = _lib.aes_ctr_crypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(counter),
                            _to_u8_ptr(data), (c_uint8 * len(out)).from_buffer(out), len(data))
    _check_rc(rc)
    return bytes(out)


def ccm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"", tag_len: int = 16) -> Tuple[bytes, bytes]:
    key_bits = _validate_key(key)
    if not (7 <= len(nonce) <= 13):
        raise ValueError("CCM nonce length must be between 7 and 13 bytes.")
    if tag_len not in (4, 6, 8, 10, 12, 14, 16):
        raise ValueError("CCM tag length must be an even integer between 4 and 16.")
    out = bytearray(len(plaintext))
    tag = bytearray(tag_len)
    rc = _lib.aes_ccm_encrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(nonce), len(nonce),
                              _to_u8_ptr(aad) if aad else None, len(aad),
                              _to_u8_ptr(plaintext), len(plaintext),
                              (c_uint8 * len(out)).from_buffer(out),
                              (c_uint8 * tag_len).from_buffer(tag), tag_len)
    _check_rc(rc)
    return bytes(out), bytes(tag)


def ccm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    key_bits = _validate_key(key)
    if not (7 <= len(nonce) <= 13):
        raise ValueError("CCM nonce length must be between 7 and 13 bytes.")
    out = bytearray(len(ciphertext))
    rc = _lib.aes_ccm_decrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(nonce), len(nonce),
                              _to_u8_ptr(aad) if aad else None, len(aad),
                              _to_u8_ptr(ciphertext), len(ciphertext),
                              (c_uint8 * len(out)).from_buffer(out),
                              _to_u8_ptr(tag), len(tag))
    _check_rc(rc)
    return bytes(out)


def gcm_encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"", tag_len: int = 16) -> Tuple[bytes, bytes]:
    key_bits = _validate_key(key)
    if len(iv) == 0:
        raise ValueError("GCM IV must not be empty.")
    if not (4 <= tag_len <= 16):
        raise ValueError("GCM tag length must be between 4 and 16 bytes.")
    out = bytearray(len(plaintext))
    tag = bytearray(tag_len)
    rc = _lib.aes_gcm_encrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(iv), len(iv),
                              _to_u8_ptr(aad) if aad else None, len(aad),
                              _to_u8_ptr(plaintext), len(plaintext),
                              (c_uint8 * len(out)).from_buffer(out),
                              (c_uint8 * tag_len).from_buffer(tag), tag_len)
    _check_rc(rc)
    return bytes(out), bytes(tag)


def gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    key_bits = _validate_key(key)
    if len(iv) == 0:
        raise ValueError("GCM IV must not be empty.")
    out = bytearray(len(ciphertext))
    rc = _lib.aes_gcm_decrypt(_to_u8_ptr(key), key_bits, _to_u8_ptr(iv), len(iv),
                              _to_u8_ptr(aad) if aad else None, len(aad),
                              _to_u8_ptr(ciphertext), len(ciphertext),
                              (c_uint8 * len(out)).from_buffer(out),
                              _to_u8_ptr(tag), len(tag))
    _check_rc(rc)
    return bytes(out)


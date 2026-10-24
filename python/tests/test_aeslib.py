"""
test_aeslib.py - Pytest suite for aeslib.py

Tests:
1. SP 800-38A Known Answer Tests (ECB, CBC, CFB, OFB, CTR)
2. SP 800-38C CCM Tests
3. SP 800-38D GCM Tests
4. Error / Exception handling (auth failure, invalid key, etc.)
5. Cross-validation against standard Python `cryptography` library
"""

import os
import sys
import pytest

# Ensure python/ is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import aeslib
from aeslib import AuthenticationError, InvalidKeyError, InvalidParamError

# Try importing cryptography for cross-validation
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as crypto_modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ============================================================
#  1. Basic & Version
# ============================================================
def test_version():
    ver = aeslib.version()
    assert "AES-Suite" in ver
    assert "FIPS 197" in ver


# ============================================================
#  2. SP 800-38A Modes
# ============================================================
KEY_128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV_128  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PT_64   = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)

def test_ecb_roundtrip():
    ct = aeslib.ecb_encrypt(KEY_128, PT_64)
    # NIST SP 800-38A F.1.1 expected first block
    assert ct[:16] == bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    dec = aeslib.ecb_decrypt(KEY_128, ct)
    assert dec == PT_64


def test_cbc_roundtrip():
    ct = aeslib.cbc_encrypt(KEY_128, IV_128, PT_64)
    # NIST SP 800-38A F.2.1 expected first block
    assert ct[:16] == bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    dec = aeslib.cbc_decrypt(KEY_128, IV_128, ct)
    assert dec == PT_64


def test_cfb128_roundtrip():
    ct = aeslib.cfb_encrypt(KEY_128, IV_128, PT_64, segment_bits=128)
    assert ct[:16] == bytes.fromhex("3b3fd92eb72dad20333449f8e83cfb4a")
    dec = aeslib.cfb_decrypt(KEY_128, IV_128, ct, segment_bits=128)
    assert dec == PT_64


def test_cfb8_roundtrip():
    pt18 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d")
    ct = aeslib.cfb_encrypt(KEY_128, IV_128, pt18, segment_bits=8)
    assert ct == bytes.fromhex("3b79424c9c0dd436bace9e0ed4586a4f32b9")
    dec = aeslib.cfb_decrypt(KEY_128, IV_128, ct, segment_bits=8)
    assert dec == pt18


def test_ofb_roundtrip():
    ct = aeslib.ofb_encrypt(KEY_128, IV_128, PT_64)
    assert ct[:16] == bytes.fromhex("3b3fd92eb72dad20333449f8e83cfb4a")
    dec = aeslib.ofb_decrypt(KEY_128, IV_128, ct)
    assert dec == PT_64


def test_ctr_roundtrip():
    counter = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    ct = aeslib.ctr_crypt(KEY_128, counter, PT_64)
    assert ct[:16] == bytes.fromhex("874d6191b620e3261bef6864990db6ce")
    dec = aeslib.ctr_crypt(KEY_128, counter, ct)
    assert dec == PT_64


# ============================================================
#  3. SP 800-38C CCM
# ============================================================
def test_ccm_nist_example():
    # Example 1
    key = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
    nonce = bytes.fromhex("10111213141516")
    aad = bytes.fromhex("0001020304050607")
    pt = bytes.fromhex("20212223")

    ct, tag = aeslib.ccm_encrypt(key, nonce, pt, aad, tag_len=4)
    assert ct == bytes.fromhex("7162015b")
    assert tag == bytes.fromhex("4dac255d")

    dec = aeslib.ccm_decrypt(key, nonce, ct, tag, aad)
    assert dec == pt

    # Negative test: invalid tag
    bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
    with pytest.raises(AuthenticationError):
        aeslib.ccm_decrypt(key, nonce, ct, bad_tag, aad)


# ============================================================
#  4. SP 800-38D GCM
# ============================================================
def test_gcm_test_case_4():
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    iv = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    pt = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")

    ct, tag = aeslib.gcm_encrypt(key, iv, pt, aad, tag_len=16)
    assert ct == bytes.fromhex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
    assert tag == bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")

    dec = aeslib.gcm_decrypt(key, iv, ct, tag, aad)
    assert dec == pt

    # Negative: bad tag
    bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
    with pytest.raises(AuthenticationError):
        aeslib.gcm_decrypt(key, iv, ct, bad_tag, aad)


def test_gcm_non_96_bit_iv():
    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    iv = bytes.fromhex("cafebabefacedbad") # 8 bytes
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    pt = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")

    ct, tag = aeslib.gcm_encrypt(key, iv, pt, aad, tag_len=16)
    assert ct == bytes.fromhex("61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598")
    assert tag == bytes.fromhex("3612d2e79e3b0785561be14aaca2fccb")

    dec = aeslib.gcm_decrypt(key, iv, ct, tag, aad)
    assert dec == pt


# ============================================================
#  5. Error Handling Tests
# ============================================================
def test_invalid_key_length():
    with pytest.raises(ValueError):
        aeslib.ecb_encrypt(b"too_short_key", PT_64)


def test_invalid_iv_length():
    with pytest.raises(ValueError):
        aeslib.cbc_encrypt(KEY_128, b"short_iv", PT_64)


def test_unaligned_ecb_input():
    with pytest.raises(ValueError):
        aeslib.ecb_encrypt(KEY_128, b"not_16_multiple")


# ============================================================
#  6. Cross-Validation against `cryptography`
# ============================================================
@pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography library not installed")
def test_cross_validate_gcm():
    import secrets
    for key_len in (16, 24, 32):
        key = secrets.token_bytes(key_len)
        iv = secrets.token_bytes(12)
        aad = secrets.token_bytes(37)
        pt = secrets.token_bytes(1024)

        # Cryptography
        cg_aesgcm = AESGCM(key)
        cg_ct_tag = cg_aesgcm.encrypt(iv, pt, aad)
        cg_ct = cg_ct_tag[:-16]
        cg_tag = cg_ct_tag[-16:]

        # aeslib
        my_ct, my_tag = aeslib.gcm_encrypt(key, iv, pt, aad, 16)

        assert my_ct == cg_ct
        assert my_tag == cg_tag

        # Cross-decrypt
        my_dec = aeslib.gcm_decrypt(key, iv, cg_ct, cg_tag, aad)
        assert my_dec == pt


@pytest.mark.skipif(not HAS_CRYPTOGRAPHY, reason="cryptography library not installed")
def test_cross_validate_cbc():
    import secrets
    for key_len in (16, 24, 32):
        key = secrets.token_bytes(key_len)
        iv = secrets.token_bytes(16)
        pt = secrets.token_bytes(512)

        # Cryptography
        backend = Cipher(algorithms.AES(key), crypto_modes.CBC(iv))
        enc = backend.encryptor()
        cg_ct = enc.update(pt) + enc.finalize()

        # aeslib
        my_ct = aeslib.cbc_encrypt(key, iv, pt)
        assert my_ct == cg_ct
        assert aeslib.cbc_decrypt(key, iv, my_ct) == pt


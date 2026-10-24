/*
 * aes_modes.h - AES Modes of Operation
 *
 * Implements:
 *   SP 800-38A: ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR
 *   SP 800-38C: CCM (AEAD)
 *   SP 800-38D: GCM (AEAD) with 96-bit and arbitrary-length IV
 *
 * Error codes are returned as int (enum AesError).
 * Tag comparison uses constant-time comparison.
 */

#ifndef AES_MODES_H_INCLUDED
#define AES_MODES_H_INCLUDED

#include "aes.h"

/* ============================================================
 *  Error codes
 * ============================================================ */
enum AesError : int {
    AES_SUCCESS           =  0,
    AES_ERR_INVALID_KEY   = -1,
    AES_ERR_INVALID_IV    = -2,
    AES_ERR_INVALID_INPUT = -3,
    AES_ERR_AUTH_FAILED   = -4,
    AES_ERR_INVALID_TAG   = -5,
    AES_ERR_INVALID_NONCE = -6,
    AES_ERR_INVALID_PARAM = -7,
    AES_ERR_BUFFER_TOO_SMALL = -8,
};

/* ============================================================
 *  SP 800-38A: ECB Mode
 * ============================================================ */
class AES_API AES_ECB {
public:
    AES_ECB() = default;
    int init(const uint8_t* key, int key_bits);
    int encrypt(const uint8_t* plain, uint8_t* cipher, size_t len) const;
    int decrypt(const uint8_t* cipher, uint8_t* plain, size_t len) const;
private:
    AESContext ctx_;
};

/* ============================================================
 *  SP 800-38A: CBC Mode
 * ============================================================ */
class AES_API AES_CBC {
public:
    AES_CBC() = default;
    int init(const uint8_t* key, int key_bits);
    int encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const;
    int decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const;
private:
    AESContext ctx_;
};

/* ============================================================
 *  SP 800-38A: CFB Mode (1, 8, or 128-bit segments)
 * ============================================================ */
class AES_API AES_CFB {
public:
    AES_CFB() : segment_bits_(128) {}
    int init(const uint8_t* key, int key_bits, int segment_bits = 128);
    // For CFB1: len is in BITS. For CFB8/CFB128: len is in BYTES.
    int encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const;
    int decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const;
private:
    AESContext ctx_;
    int segment_bits_;

    int cfb1_encrypt(const uint8_t* plain, uint8_t* cipher, size_t num_bits, const uint8_t iv[16]) const;
    int cfb1_decrypt(const uint8_t* cipher, uint8_t* plain, size_t num_bits, const uint8_t iv[16]) const;
    int cfb8_encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const;
    int cfb8_decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const;
    int cfb128_encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const;
    int cfb128_decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const;
};

/* ============================================================
 *  SP 800-38A: OFB Mode
 * ============================================================ */
class AES_API AES_OFB {
public:
    AES_OFB() = default;
    int init(const uint8_t* key, int key_bits);
    int encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const;
    int decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const;
private:
    AESContext ctx_;
};

/* ============================================================
 *  SP 800-38A: CTR Mode
 * ============================================================ */
class AES_API AES_CTR {
public:
    AES_CTR() = default;
    int init(const uint8_t* key, int key_bits);
    // counter is the initial counter block (16 bytes, big-endian)
    int encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t counter[16]) const;
    int decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t counter[16]) const;
private:
    AESContext ctx_;
    // Increment the entire 128-bit counter (big-endian)
    static void inc128(uint8_t ctr[16]);
};

/* ============================================================
 *  SP 800-38C: CCM Mode (AEAD)
 * ============================================================ */
class AES_API AES_CCM {
public:
    AES_CCM() = default;
    int init(const uint8_t* key, int key_bits);

    // tag_len: 4,6,8,10,12,14,16 (in bytes)
    // nonce_len: 7..13
    int encrypt(const uint8_t* nonce, size_t nonce_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* plain, size_t plain_len,
                uint8_t* cipher, uint8_t* tag, size_t tag_len) const;

    // Returns AES_ERR_AUTH_FAILED if tag verification fails.
    // On auth failure, plaintext output is zeroed.
    int decrypt(const uint8_t* nonce, size_t nonce_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* cipher, size_t cipher_len,
                uint8_t* plain, const uint8_t* tag, size_t tag_len) const;
private:
    AESContext ctx_;

    void format_b0(uint8_t b0[16], const uint8_t* nonce, size_t nonce_len,
                   size_t aad_len, size_t plain_len, size_t tag_len) const;
    void cbc_mac_aad(uint8_t mac[16], const uint8_t* aad, size_t aad_len) const;
    void cbc_mac_payload(uint8_t mac[16], const uint8_t* data, size_t data_len) const;
    void ctr_crypt(const uint8_t* nonce, size_t nonce_len,
                   const uint8_t* in, uint8_t* out, size_t len) const;
    // inc32 for CCM counter (last L bytes)
    static void inc_ctr_ccm(uint8_t ctr[16], int L);
};

/* ============================================================
 *  GCM: GHASH helper (precomputed position-nibble table)
 * ============================================================ */
struct AES_API GHashCtx {
    // 32 nibble positions x 16 nibble values (8 KB total, fits in L1 cache)
    uint64_t th[32][16];
    uint64_t tl[32][16];

    void init(const uint8_t H[16]);
    void ghash(const uint8_t* data, size_t len, uint8_t tag[16]) const;
    void ghash_update(uint8_t tag[16], const uint8_t* data, size_t len) const;
};

/* ============================================================
 *  SP 800-38D: GCM Mode (AEAD)
 * ============================================================ */
class AES_API AES_GCM {
public:
    AES_GCM() = default;
    int init(const uint8_t* key, int key_bits);

    // tag_len: 4..16 bytes (spec allows 12,13,14,15,16 and 4,8 for certain apps)
    // iv can be any length; 96-bit is recommended (fast path)
    int encrypt(const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* plain, size_t plain_len,
                uint8_t* cipher, uint8_t* tag, size_t tag_len) const;

    int decrypt(const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* cipher, size_t cipher_len,
                uint8_t* plain, const uint8_t* tag, size_t tag_len) const;

private:
    AESContext ctx_;
    GHashCtx ghash_ctx_;

    void compute_j0(const uint8_t* iv, size_t iv_len, uint8_t j0[16]) const;
    void gctr(const uint8_t* icb, const uint8_t* in, uint8_t* out, size_t len) const;
    // inc32: increment rightmost 32 bits of counter
    static void inc32(uint8_t ctr[16]);
};

#endif // AES_MODES_H_INCLUDED

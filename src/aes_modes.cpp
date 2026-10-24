/*
 * aes_modes.cpp - AES Modes of Operation Implementation
 *
 * SP 800-38A: ECB, CBC, CFB1, CFB8, CFB128, OFB, CTR
 * SP 800-38C: CCM
 * SP 800-38D: GCM (with GHASH 4-bit table)
 */

#include "aes_modes.h"
#include <algorithm>

using namespace aes_impl;

/* ============================================================
 *  ECB
 * ============================================================ */
int AES_ECB::init(const uint8_t* key, int key_bits) {
    return ctx_.init(key, key_bits) ? AES_SUCCESS : AES_ERR_INVALID_KEY;
}

int AES_ECB::encrypt(const uint8_t* plain, uint8_t* cipher, size_t len) const {
    if (len == 0) return AES_SUCCESS;
    if (len % 16 != 0) return AES_ERR_INVALID_INPUT;
    for (size_t i = 0; i < len; i += 16)
        ctx_.encrypt_block(plain + i, cipher + i);
    return AES_SUCCESS;
}

int AES_ECB::decrypt(const uint8_t* cipher, uint8_t* plain, size_t len) const {
    if (len == 0) return AES_SUCCESS;
    if (len % 16 != 0) return AES_ERR_INVALID_INPUT;
    for (size_t i = 0; i < len; i += 16)
        ctx_.decrypt_block(cipher + i, plain + i);
    return AES_SUCCESS;
}

/* ============================================================
 *  CBC
 * ============================================================ */
int AES_CBC::init(const uint8_t* key, int key_bits) {
    return ctx_.init(key, key_bits) ? AES_SUCCESS : AES_ERR_INVALID_KEY;
}

int AES_CBC::encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const {
    if (len == 0) return AES_SUCCESS;
    if (len % 16 != 0) return AES_ERR_INVALID_INPUT;

    uint8_t block[16];
    const uint8_t* prev = iv;

    for (size_t i = 0; i < len; i += 16) {
        xor_block(block, plain + i, prev, 16);
        ctx_.encrypt_block(block, cipher + i);
        prev = cipher + i;
    }
    return AES_SUCCESS;
}

int AES_CBC::decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const {
    if (len == 0) return AES_SUCCESS;
    if (len % 16 != 0) return AES_ERR_INVALID_INPUT;

    uint8_t block[16];
    const uint8_t* prev = iv;

    for (size_t i = 0; i < len; i += 16) {
        ctx_.decrypt_block(cipher + i, block);
        xor_block(plain + i, block, prev, 16);
        prev = cipher + i;
    }
    return AES_SUCCESS;
}

/* ============================================================
 *  CFB
 * ============================================================ */
int AES_CFB::init(const uint8_t* key, int key_bits, int segment_bits) {
    if (segment_bits != 1 && segment_bits != 8 && segment_bits != 128)
        return AES_ERR_INVALID_PARAM;
    segment_bits_ = segment_bits;
    return ctx_.init(key, key_bits) ? AES_SUCCESS : AES_ERR_INVALID_KEY;
}

/* --- CFB1: Process 1 bit at a time --- */
int AES_CFB::cfb1_encrypt(const uint8_t* plain, uint8_t* cipher, size_t num_bits, const uint8_t iv[16]) const {
    uint8_t shift_reg[16];
    uint8_t out_block[16];
    std::memcpy(shift_reg, iv, 16);

    // Clear output
    size_t num_bytes = (num_bits + 7) / 8;
    std::memset(cipher, 0, num_bytes);

    for (size_t i = 0; i < num_bits; ++i) {
        ctx_.encrypt_block(shift_reg, out_block);

        // MSB of output
        uint8_t out_bit = (out_block[0] >> 7) & 1;
        // Input bit
        uint8_t in_bit = (plain[i / 8] >> (7 - (i % 8))) & 1;
        // Cipher bit
        uint8_t cipher_bit = in_bit ^ out_bit;

        // Set cipher bit
        cipher[i / 8] |= static_cast<uint8_t>(cipher_bit << (7 - (i % 8)));

        // Shift register left by 1 bit, feed cipher_bit at LSB
        for (int j = 0; j < 15; ++j) {
            shift_reg[j] = static_cast<uint8_t>((shift_reg[j] << 1) | (shift_reg[j + 1] >> 7));
        }
        shift_reg[15] = static_cast<uint8_t>((shift_reg[15] << 1) | cipher_bit);
    }
    return AES_SUCCESS;
}

int AES_CFB::cfb1_decrypt(const uint8_t* cipher, uint8_t* plain, size_t num_bits, const uint8_t iv[16]) const {
    uint8_t shift_reg[16];
    uint8_t out_block[16];
    std::memcpy(shift_reg, iv, 16);

    size_t num_bytes = (num_bits + 7) / 8;
    std::memset(plain, 0, num_bytes);

    for (size_t i = 0; i < num_bits; ++i) {
        ctx_.encrypt_block(shift_reg, out_block);

        uint8_t out_bit = (out_block[0] >> 7) & 1;
        uint8_t cipher_bit = (cipher[i / 8] >> (7 - (i % 8))) & 1;
        uint8_t plain_bit = cipher_bit ^ out_bit;

        plain[i / 8] |= static_cast<uint8_t>(plain_bit << (7 - (i % 8)));

        // Shift register left by 1 bit, feed cipher_bit at LSB
        for (int j = 0; j < 15; ++j) {
            shift_reg[j] = static_cast<uint8_t>((shift_reg[j] << 1) | (shift_reg[j + 1] >> 7));
        }
        shift_reg[15] = static_cast<uint8_t>((shift_reg[15] << 1) | cipher_bit);
    }
    return AES_SUCCESS;
}

/* --- CFB8: Process 1 byte at a time --- */
int AES_CFB::cfb8_encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const {
    uint8_t shift_reg[16];
    uint8_t out_block[16];
    std::memcpy(shift_reg, iv, 16);

    for (size_t i = 0; i < len; ++i) {
        ctx_.encrypt_block(shift_reg, out_block);
        cipher[i] = plain[i] ^ out_block[0];
        std::memmove(shift_reg, shift_reg + 1, 15);
        shift_reg[15] = cipher[i];
    }
    return AES_SUCCESS;
}

int AES_CFB::cfb8_decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const {
    uint8_t shift_reg[16];
    uint8_t out_block[16];
    std::memcpy(shift_reg, iv, 16);

    for (size_t i = 0; i < len; ++i) {
        ctx_.encrypt_block(shift_reg, out_block);
        plain[i] = cipher[i] ^ out_block[0];
        std::memmove(shift_reg, shift_reg + 1, 15);
        shift_reg[15] = cipher[i];
    }
    return AES_SUCCESS;
}

/* --- CFB128: Process 16 bytes at a time --- */
int AES_CFB::cfb128_encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const {
    if (len % 16 != 0) return AES_ERR_INVALID_INPUT;

    uint8_t inp[16], out[16];
    std::memcpy(inp, iv, 16);

    for (size_t i = 0; i < len; i += 16) {
        ctx_.encrypt_block(inp, out);
        xor_block(cipher + i, plain + i, out, 16);
        std::memcpy(inp, cipher + i, 16);
    }
    return AES_SUCCESS;
}

int AES_CFB::cfb128_decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const {
    if (len % 16 != 0) return AES_ERR_INVALID_INPUT;

    uint8_t inp[16], out[16];
    std::memcpy(inp, iv, 16);

    for (size_t i = 0; i < len; i += 16) {
        ctx_.encrypt_block(inp, out);
        std::memcpy(inp, cipher + i, 16);  // save cipher before overwrite
        xor_block(plain + i, cipher + i, out, 16);
    }
    return AES_SUCCESS;
}

/* --- CFB dispatch --- */
int AES_CFB::encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const {
    switch (segment_bits_) {
        case 1:   return cfb1_encrypt(plain, cipher, len, iv);  // len = num_bits
        case 8:   return cfb8_encrypt(plain, cipher, len, iv);
        case 128: return cfb128_encrypt(plain, cipher, len, iv);
        default:  return AES_ERR_INVALID_PARAM;
    }
}

int AES_CFB::decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const {
    switch (segment_bits_) {
        case 1:   return cfb1_decrypt(cipher, plain, len, iv);
        case 8:   return cfb8_decrypt(cipher, plain, len, iv);
        case 128: return cfb128_decrypt(cipher, plain, len, iv);
        default:  return AES_ERR_INVALID_PARAM;
    }
}

/* ============================================================
 *  OFB
 * ============================================================ */
int AES_OFB::init(const uint8_t* key, int key_bits) {
    return ctx_.init(key, key_bits) ? AES_SUCCESS : AES_ERR_INVALID_KEY;
}

int AES_OFB::encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t iv[16]) const {
    if (len == 0) return AES_SUCCESS;
    if (len % 16 != 0) return AES_ERR_INVALID_INPUT;

    uint8_t fb[16];
    std::memcpy(fb, iv, 16);

    for (size_t i = 0; i < len; i += 16) {
        ctx_.encrypt_block(fb, fb);
        xor_block(cipher + i, plain + i, fb, 16);
    }
    return AES_SUCCESS;
}

int AES_OFB::decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t iv[16]) const {
    return encrypt(cipher, plain, len, iv);  // OFB encrypt == decrypt
}

/* ============================================================
 *  CTR
 * ============================================================ */
int AES_CTR::init(const uint8_t* key, int key_bits) {
    return ctx_.init(key, key_bits) ? AES_SUCCESS : AES_ERR_INVALID_KEY;
}

void AES_CTR::inc128(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++ctr[i] != 0) break;
    }
}

int AES_CTR::encrypt(const uint8_t* plain, uint8_t* cipher, size_t len, const uint8_t counter[16]) const {
    if (len == 0) return AES_SUCCESS;

    uint8_t ctr[16], ks[16];
    std::memcpy(ctr, counter, 16);

    size_t full_blocks = len / 16;
    size_t remainder = len % 16;

    for (size_t i = 0; i < full_blocks; ++i) {
        ctx_.encrypt_block(ctr, ks);
        xor_block(cipher + i * 16, plain + i * 16, ks, 16);
        inc128(ctr);
    }

    if (remainder > 0) {
        ctx_.encrypt_block(ctr, ks);
        xor_block(cipher + full_blocks * 16, plain + full_blocks * 16, ks, remainder);
    }

    return AES_SUCCESS;
}

int AES_CTR::decrypt(const uint8_t* cipher, uint8_t* plain, size_t len, const uint8_t counter[16]) const {
    return encrypt(cipher, plain, len, counter);  // CTR encrypt == decrypt
}

/* ============================================================
 *  CCM (SP 800-38C)
 * ============================================================ */
int AES_CCM::init(const uint8_t* key, int key_bits) {
    return ctx_.init(key, key_bits) ? AES_SUCCESS : AES_ERR_INVALID_KEY;
}

void AES_CCM::inc_ctr_ccm(uint8_t ctr[16], int L) {
    for (int i = 15; i >= 16 - L; --i) {
        if (++ctr[i] != 0) break;
    }
}

void AES_CCM::format_b0(uint8_t b0[16], const uint8_t* nonce, size_t nonce_len,
                          size_t aad_len, size_t plain_len, size_t tag_len) const {
    std::memset(b0, 0, 16);
    int q = static_cast<int>(15 - nonce_len); // L = q
    uint8_t flags = 0;
    if (aad_len > 0) flags |= 0x40;  // Adata flag
    flags |= static_cast<uint8_t>(((tag_len - 2) / 2) << 3); // (t-2)/2 encoded in bits 5..3
    flags |= static_cast<uint8_t>(q - 1); // q-1 encoded in bits 2..0
    b0[0] = flags;
    std::memcpy(b0 + 1, nonce, nonce_len);
    // Encode payload length Q in big-endian in last q bytes
    for (int i = 0; i < q; ++i) {
        b0[15 - i] = static_cast<uint8_t>(plain_len >> (8 * i));
    }
}

void AES_CCM::cbc_mac_aad(uint8_t mac[16], const uint8_t* aad, size_t aad_len) const {
    if (aad_len == 0) return;

    uint8_t block[16];
    std::memset(block, 0, 16);

    // Encode AAD length
    size_t header_len;
    if (aad_len < 0xFF00ULL) {
        // 0 < a < 2^16 - 2^8: 2 bytes
        block[0] = static_cast<uint8_t>(aad_len >> 8);
        block[1] = static_cast<uint8_t>(aad_len);
        header_len = 2;
    } else if (aad_len < 0x100000000ULL) {
        // 2^16 - 2^8 <= a < 2^32: 0xFFFE + 4 bytes
        block[0] = 0xFF;
        block[1] = 0xFE;
        block[2] = static_cast<uint8_t>(aad_len >> 24);
        block[3] = static_cast<uint8_t>(aad_len >> 16);
        block[4] = static_cast<uint8_t>(aad_len >> 8);
        block[5] = static_cast<uint8_t>(aad_len);
        header_len = 6;
    } else {
        block[0] = 0xFF;
        block[1] = 0xFF;
        block[2] = static_cast<uint8_t>(aad_len >> 56);
        block[3] = static_cast<uint8_t>(aad_len >> 48);
        block[4] = static_cast<uint8_t>(aad_len >> 40);
        block[5] = static_cast<uint8_t>(aad_len >> 32);
        block[6] = static_cast<uint8_t>(aad_len >> 24);
        block[7] = static_cast<uint8_t>(aad_len >> 16);
        block[8] = static_cast<uint8_t>(aad_len >> 8);
        block[9] = static_cast<uint8_t>(aad_len);
        header_len = 10;
    }

    // Fill first block with AAD length header + start of AAD
    size_t copy_len = std::min(aad_len, static_cast<size_t>(16 - header_len));
    std::memcpy(block + header_len, aad, copy_len);

    xor_block_inplace(mac, block, 16);
    ctx_.encrypt_block(mac, mac);

    size_t offset = copy_len;
    while (offset < aad_len) {
        std::memset(block, 0, 16);
        size_t chunk = std::min(static_cast<size_t>(16), aad_len - offset);
        std::memcpy(block, aad + offset, chunk);
        xor_block_inplace(mac, block, 16);
        ctx_.encrypt_block(mac, mac);
        offset += chunk;
    }
}

void AES_CCM::cbc_mac_payload(uint8_t mac[16], const uint8_t* data, size_t data_len) const {
    size_t offset = 0;
    while (offset < data_len) {
        uint8_t block[16];
        std::memset(block, 0, 16);
        size_t chunk = std::min(static_cast<size_t>(16), data_len - offset);
        std::memcpy(block, data + offset, chunk);
        xor_block_inplace(mac, block, 16);
        ctx_.encrypt_block(mac, mac);
        offset += chunk;
    }
}

void AES_CCM::ctr_crypt(const uint8_t* nonce, size_t nonce_len,
                          const uint8_t* in, uint8_t* out, size_t len) const {
    int q = static_cast<int>(15 - nonce_len);
    uint8_t ctr[16];
    std::memset(ctr, 0, 16);
    ctr[0] = static_cast<uint8_t>(q - 1);  // Flags for counter
    std::memcpy(ctr + 1, nonce, nonce_len);
    // Counter starts at 1 for payload (counter 0 is for tag encryption)
    ctr[15] = 1;

    uint8_t ks[16];
    size_t offset = 0;
    while (offset < len) {
        ctx_.encrypt_block(ctr, ks);
        size_t chunk = std::min(static_cast<size_t>(16), len - offset);
        xor_block(out + offset, in + offset, ks, chunk);
        inc_ctr_ccm(ctr, q);
        offset += chunk;
    }
}

int AES_CCM::encrypt(const uint8_t* nonce, size_t nonce_len,
                      const uint8_t* aad, size_t aad_len,
                      const uint8_t* plain, size_t plain_len,
                      uint8_t* cipher, uint8_t* tag, size_t tag_len) const {
    // Validate parameters
    if (nonce_len < 7 || nonce_len > 13) return AES_ERR_INVALID_NONCE;
    if (tag_len < 4 || tag_len > 16 || (tag_len & 1)) return AES_ERR_INVALID_TAG;

    int q = static_cast<int>(15 - nonce_len);
    // Check that payload length fits in q bytes
    if (q < 8) {
        uint64_t max_len = (1ULL << (8 * q)) - 1;
        if (plain_len > max_len) return AES_ERR_INVALID_INPUT;
    }

    // Step 1: CBC-MAC to compute T
    uint8_t mac[16];
    uint8_t b0[16];
    format_b0(b0, nonce, nonce_len, aad_len, plain_len, tag_len);
    std::memset(mac, 0, 16);
    xor_block_inplace(mac, b0, 16);
    ctx_.encrypt_block(mac, mac);

    // Process AAD
    cbc_mac_aad(mac, aad, aad_len);

    // Process plaintext
    cbc_mac_payload(mac, plain, plain_len);

    // Step 2: CTR encryption of plaintext
    ctr_crypt(nonce, nonce_len, plain, cipher, plain_len);

    // Step 3: Encrypt MAC with counter 0 to get tag
    uint8_t ctr0[16];
    std::memset(ctr0, 0, 16);
    ctr0[0] = static_cast<uint8_t>(q - 1);
    std::memcpy(ctr0 + 1, nonce, nonce_len);
    // counter = 0 (already zeroed)

    uint8_t s0[16];
    ctx_.encrypt_block(ctr0, s0);
    for (size_t i = 0; i < tag_len; ++i)
        tag[i] = mac[i] ^ s0[i];

    return AES_SUCCESS;
}

int AES_CCM::decrypt(const uint8_t* nonce, size_t nonce_len,
                      const uint8_t* aad, size_t aad_len,
                      const uint8_t* cipher, size_t cipher_len,
                      uint8_t* plain, const uint8_t* tag, size_t tag_len) const {
    if (nonce_len < 7 || nonce_len > 13) return AES_ERR_INVALID_NONCE;
    if (tag_len < 4 || tag_len > 16 || (tag_len & 1)) return AES_ERR_INVALID_TAG;

    int q = static_cast<int>(15 - nonce_len);

    // Step 1: CTR decrypt ciphertext
    ctr_crypt(nonce, nonce_len, cipher, plain, cipher_len);

    // Step 2: CBC-MAC to verify
    uint8_t mac[16];
    uint8_t b0[16];
    format_b0(b0, nonce, nonce_len, aad_len, cipher_len, tag_len);
    std::memset(mac, 0, 16);
    xor_block_inplace(mac, b0, 16);
    ctx_.encrypt_block(mac, mac);

    cbc_mac_aad(mac, aad, aad_len);
    cbc_mac_payload(mac, plain, cipher_len);

    // Encrypt MAC with counter 0
    uint8_t ctr0[16];
    std::memset(ctr0, 0, 16);
    ctr0[0] = static_cast<uint8_t>(q - 1);
    std::memcpy(ctr0 + 1, nonce, nonce_len);

    uint8_t s0[16];
    ctx_.encrypt_block(ctr0, s0);

    uint8_t computed_tag[16];
    for (size_t i = 0; i < tag_len; ++i)
        computed_tag[i] = mac[i] ^ s0[i];

    if (!constant_time_eq(computed_tag, tag, tag_len)) {
        // Authentication failed — zero plaintext
        secure_zero(plain, cipher_len);
        return AES_ERR_AUTH_FAILED;
    }

    return AES_SUCCESS;
}

/* ============================================================
 *  GHASH (Position-nibble table method, 8 KB table in L1 cache)
 * ============================================================ */
static void gf128_from_bytes(const uint8_t src[16], uint64_t& hi, uint64_t& lo) {
    hi = lo = 0;
    for (int i = 0; i < 8; ++i) {
        hi = (hi << 8) | src[i];
        lo = (lo << 8) | src[i + 8];
    }
}

static void gf128_to_bytes(uint64_t hi, uint64_t lo, uint8_t dst[16]) {
    for (int i = 7; i >= 0; --i) {
        dst[i] = static_cast<uint8_t>(hi); hi >>= 8;
        dst[i + 8] = static_cast<uint8_t>(lo); lo >>= 8;
    }
}

static void gf128_mul_u(uint64_t& vh, uint64_t& vl) {
    uint64_t carry = vl & 1;
    vl = (vl >> 1) | (vh << 63);
    vh = (vh >> 1) ^ (carry ? 0xE100000000000000ULL : 0);
}

void GHashCtx::init(const uint8_t H[16]) {
    // Generate 128 powers of H: V[0] = H, V[i+1] = V[i] * u
    uint64_t Vh[128], Vl[128];
    gf128_from_bytes(H, Vh[0], Vl[0]);
    for (int i = 1; i < 128; ++i) {
        Vh[i] = Vh[i - 1];
        Vl[i] = Vl[i - 1];
        gf128_mul_u(Vh[i], Vl[i]);
    }

    // Precompute 32 nibble tables: th/tl[pos][val]
    for (int pos = 0; pos < 32; ++pos) {
        int bit_base = pos * 4;
        for (int val = 0; val < 16; ++val) {
            uint64_t zh = 0, zl = 0;
            if (val & 8) { zh ^= Vh[bit_base + 0]; zl ^= Vl[bit_base + 0]; }
            if (val & 4) { zh ^= Vh[bit_base + 1]; zl ^= Vl[bit_base + 1]; }
            if (val & 2) { zh ^= Vh[bit_base + 2]; zl ^= Vl[bit_base + 2]; }
            if (val & 1) { zh ^= Vh[bit_base + 3]; zl ^= Vl[bit_base + 3]; }
            th[pos][val] = zh;
            tl[pos][val] = zl;
        }
    }
}

void GHashCtx::ghash_update(uint8_t tag[16], const uint8_t* data, size_t len) const {
    // Process full 16-byte blocks
    for (size_t off = 0; off < len; off += 16) {
        size_t chunk = std::min(len - off, static_cast<size_t>(16));
        for (size_t i = 0; i < chunk; ++i)
            tag[i] ^= data[off + i];

        uint64_t zh = 0, zl = 0;
        for (int i = 0; i < 16; ++i) {
            uint8_t b = tag[i];
            uint8_t hi = b >> 4;
            uint8_t lo = b & 0x0f;
            zh ^= th[2 * i][hi];
            zl ^= tl[2 * i][hi];
            zh ^= th[2 * i + 1][lo];
            zl ^= tl[2 * i + 1][lo];
        }
        gf128_to_bytes(zh, zl, tag);
    }
}

void GHashCtx::ghash(const uint8_t* data, size_t len, uint8_t tag[16]) const {
    std::memset(tag, 0, 16);
    ghash_update(tag, data, len);
}

/* ============================================================
 *  GCM (SP 800-38D)
 * ============================================================ */
int AES_GCM::init(const uint8_t* key, int key_bits) {
    if (!ctx_.init(key, key_bits)) return AES_ERR_INVALID_KEY;

    // Compute H = CIPH_K(0^128)
    uint8_t H[16];
    uint8_t zero[16] = {0};
    ctx_.encrypt_block(zero, H);
    ghash_ctx_.init(H);
    secure_zero(H, 16);

    return AES_SUCCESS;
}

void AES_GCM::inc32(uint8_t ctr[16]) {
    // Increment rightmost 32 bits (big-endian)
    for (int i = 15; i >= 12; --i) {
        if (++ctr[i] != 0) break;
    }
}

void AES_GCM::compute_j0(const uint8_t* iv, size_t iv_len, uint8_t j0[16]) const {
    if (iv_len == 12) {
        // J0 = IV || 0^31 || 1
        std::memcpy(j0, iv, 12);
        j0[12] = 0;
        j0[13] = 0;
        j0[14] = 0;
        j0[15] = 1;
    } else {
        // J0 = GHASH_H(IV || 0^s || len(IV)_64)
        // where s = 128*ceil(len(IV)/128) - len(IV)
        // Pad IV to multiple of 16, then append 8 bytes of zeros and 8 bytes of bit-length
        uint8_t tag[16];
        std::memset(tag, 0, 16);

        // Process IV padded to 16-byte blocks
        size_t full_blocks = iv_len / 16;
        for (size_t i = 0; i < full_blocks; ++i) {
            ghash_ctx_.ghash_update(tag, iv + i * 16, 16);
        }

        // Last partial block (padded with zeros)
        size_t rem = iv_len % 16;
        if (rem > 0) {
            uint8_t pad[16] = {0};
            std::memcpy(pad, iv + full_blocks * 16, rem);
            ghash_ctx_.ghash_update(tag, pad, 16);
        }

        // Append 64-bit zero || 64-bit length in bits
        uint8_t len_block[16] = {0};
        uint64_t iv_bits = static_cast<uint64_t>(iv_len) * 8;
        for (int i = 7; i >= 0; --i) {
            len_block[8 + i] = static_cast<uint8_t>(iv_bits);
            iv_bits >>= 8;
        }
        ghash_ctx_.ghash_update(tag, len_block, 16);

        std::memcpy(j0, tag, 16);
    }
}

void AES_GCM::gctr(const uint8_t* icb, const uint8_t* in, uint8_t* out, size_t len) const {
    if (len == 0) return;

    uint8_t ctr[16], ks[16];
    std::memcpy(ctr, icb, 16);

    size_t full_blocks = len / 16;
    size_t remainder = len % 16;

    for (size_t i = 0; i < full_blocks; ++i) {
        ctx_.encrypt_block(ctr, ks);
        xor_block(out + i * 16, in + i * 16, ks, 16);
        inc32(ctr);
    }

    if (remainder > 0) {
        ctx_.encrypt_block(ctr, ks);
        xor_block(out + full_blocks * 16, in + full_blocks * 16, ks, remainder);
    }
}

int AES_GCM::encrypt(const uint8_t* iv, size_t iv_len,
                      const uint8_t* aad, size_t aad_len,
                      const uint8_t* plain, size_t plain_len,
                      uint8_t* cipher, uint8_t* tag, size_t tag_len) const {
    if (iv_len == 0) return AES_ERR_INVALID_IV;
    if (tag_len < 4 || tag_len > 16) return AES_ERR_INVALID_TAG;

    // Compute J0
    uint8_t j0[16];
    compute_j0(iv, iv_len, j0);

    // Encrypt: GCTR with ICB = inc32(J0)
    uint8_t icb[16];
    std::memcpy(icb, j0, 16);
    inc32(icb);
    gctr(icb, plain, cipher, plain_len);

    // Compute GHASH over AAD and ciphertext
    uint8_t ghash_result[16];
    std::memset(ghash_result, 0, 16);

    // Process AAD (padded to 16 bytes)
    if (aad_len > 0) {
        size_t full = aad_len / 16;
        for (size_t i = 0; i < full; ++i)
            ghash_ctx_.ghash_update(ghash_result, aad + i * 16, 16);
        size_t rem = aad_len % 16;
        if (rem > 0) {
            uint8_t pad[16] = {0};
            std::memcpy(pad, aad + full * 16, rem);
            ghash_ctx_.ghash_update(ghash_result, pad, 16);
        }
    }

    // Process ciphertext (padded to 16 bytes)
    if (plain_len > 0) {
        size_t full = plain_len / 16;
        for (size_t i = 0; i < full; ++i)
            ghash_ctx_.ghash_update(ghash_result, cipher + i * 16, 16);
        size_t rem = plain_len % 16;
        if (rem > 0) {
            uint8_t pad[16] = {0};
            std::memcpy(pad, cipher + full * 16, rem);
            ghash_ctx_.ghash_update(ghash_result, pad, 16);
        }
    }

    // Append length block: [len(A)]_64 || [len(C)]_64 in bits
    uint8_t len_block[16] = {0};
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits = static_cast<uint64_t>(plain_len) * 8;
    for (int i = 7; i >= 0; --i) {
        len_block[i] = static_cast<uint8_t>(aad_bits);
        aad_bits >>= 8;
        len_block[i + 8] = static_cast<uint8_t>(ct_bits);
        ct_bits >>= 8;
    }
    ghash_ctx_.ghash_update(ghash_result, len_block, 16);

    // Compute tag: GCTR_K(J0, S)
    uint8_t full_tag[16];
    uint8_t ks[16];
    ctx_.encrypt_block(j0, ks);
    xor_block(full_tag, ghash_result, ks, 16);

    std::memcpy(tag, full_tag, tag_len);
    return AES_SUCCESS;
}

int AES_GCM::decrypt(const uint8_t* iv, size_t iv_len,
                      const uint8_t* aad, size_t aad_len,
                      const uint8_t* cipher, size_t cipher_len,
                      uint8_t* plain, const uint8_t* tag, size_t tag_len) const {
    if (iv_len == 0) return AES_ERR_INVALID_IV;
    if (tag_len < 4 || tag_len > 16) return AES_ERR_INVALID_TAG;

    // Compute J0
    uint8_t j0[16];
    compute_j0(iv, iv_len, j0);

    // First compute GHASH over AAD and ciphertext to verify tag
    uint8_t ghash_result[16];
    std::memset(ghash_result, 0, 16);

    if (aad_len > 0) {
        size_t full = aad_len / 16;
        for (size_t i = 0; i < full; ++i)
            ghash_ctx_.ghash_update(ghash_result, aad + i * 16, 16);
        size_t rem = aad_len % 16;
        if (rem > 0) {
            uint8_t pad[16] = {0};
            std::memcpy(pad, aad + full * 16, rem);
            ghash_ctx_.ghash_update(ghash_result, pad, 16);
        }
    }

    if (cipher_len > 0) {
        size_t full = cipher_len / 16;
        for (size_t i = 0; i < full; ++i)
            ghash_ctx_.ghash_update(ghash_result, cipher + i * 16, 16);
        size_t rem = cipher_len % 16;
        if (rem > 0) {
            uint8_t pad[16] = {0};
            std::memcpy(pad, cipher + full * 16, rem);
            ghash_ctx_.ghash_update(ghash_result, pad, 16);
        }
    }

    uint8_t len_block[16] = {0};
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits = static_cast<uint64_t>(cipher_len) * 8;
    for (int i = 7; i >= 0; --i) {
        len_block[i] = static_cast<uint8_t>(aad_bits);
        aad_bits >>= 8;
        len_block[i + 8] = static_cast<uint8_t>(ct_bits);
        ct_bits >>= 8;
    }
    ghash_ctx_.ghash_update(ghash_result, len_block, 16);

    uint8_t full_tag[16];
    uint8_t ks[16];
    ctx_.encrypt_block(j0, ks);
    xor_block(full_tag, ghash_result, ks, 16);

    // Verify tag (constant-time)
    if (!constant_time_eq(full_tag, tag, tag_len)) {
        // Do NOT output plaintext
        std::memset(plain, 0, cipher_len);
        return AES_ERR_AUTH_FAILED;
    }

    // Decrypt
    uint8_t icb[16];
    std::memcpy(icb, j0, 16);
    inc32(icb);
    gctr(icb, cipher, plain, cipher_len);

    return AES_SUCCESS;
}


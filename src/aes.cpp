/*
 * aes.cpp - AES Block Cipher Implementation (FIPS 197)
 *
 * Optimized T-table implementation with:
 * - Compile-time T-table generation (constexpr)
 * - 32-bit word-oriented round keys
 * - Equivalent inverse cipher for fast decryption
 * - Safe big-endian load/store via memcpy
 * - Unrolled round functions
 * - secure_zero for key material
 *
 * NOTE: T-table lookups are vulnerable to cache-timing attacks.
 * This is an educational implementation. For production use,
 * enable AES-NI (constant-time, hardware-accelerated).
 */

#include "aes.h"
#include <stdexcept>

using namespace aes_impl;

/* ============================================================
 *  Key Expansion (FIPS 197 Section 5.2)
 * ============================================================ */
void AESContext::key_expansion(const uint8_t* key) {
    const int total = 4 * (nr_ + 1);

    // Load key into first nk_ words
    for (int i = 0; i < nk_; ++i) {
        rk_[i] = load_be32(key + 4 * i);
    }

    for (int i = nk_; i < total; ++i) {
        uint32_t temp = rk_[i - 1];
        if (i % nk_ == 0) {
            // RotWord + SubWord + Rcon
            temp = (static_cast<uint32_t>(SBOX[(temp >> 16) & 0xff]) << 24) |
                   (static_cast<uint32_t>(SBOX[(temp >> 8) & 0xff]) << 16) |
                   (static_cast<uint32_t>(SBOX[temp & 0xff]) << 8) |
                   static_cast<uint32_t>(SBOX[temp >> 24]);
            temp ^= static_cast<uint32_t>(RCON[(i / nk_) - 1]) << 24;
        } else if (nk_ > 6 && (i % nk_) == 4) {
            // SubWord only for AES-256
            temp = (static_cast<uint32_t>(SBOX[temp >> 24]) << 24) |
                   (static_cast<uint32_t>(SBOX[(temp >> 16) & 0xff]) << 16) |
                   (static_cast<uint32_t>(SBOX[(temp >> 8) & 0xff]) << 8) |
                   static_cast<uint32_t>(SBOX[temp & 0xff]);
        }
        rk_[i] = rk_[i - nk_] ^ temp;
    }
}

/* ============================================================
 *  Compute Equivalent Inverse Cipher Decrypt Keys
 *  Apply InvMixColumns to round keys 1..Nr-1
 * ============================================================ */
void AESContext::compute_decrypt_keys() {
    // First and last round keys are unchanged
    for (int i = 0; i < 4; ++i) {
        drk_[i] = rk_[4 * nr_ + i];  // decrypt starts from last round key
    }

    for (int r = 1; r < nr_; ++r) {
        for (int i = 0; i < 4; ++i) {
            uint32_t w = rk_[4 * (nr_ - r) + i];
            // Apply InvMixColumns via Td tables on each byte through SBOX
            // For equivalent inverse cipher: IMC(w) where w is already a round key
            uint8_t b0 = static_cast<uint8_t>(w >> 24);
            uint8_t b1 = static_cast<uint8_t>(w >> 16);
            uint8_t b2 = static_cast<uint8_t>(w >> 8);
            uint8_t b3 = static_cast<uint8_t>(w);

            // InvMixColumns on each column byte
            drk_[4 * r + i] = TT.Td0[SBOX[b0]] ^ TT.Td1[SBOX[b1]] ^
                               TT.Td2[SBOX[b2]] ^ TT.Td3[SBOX[b3]];
        }
    }

    for (int i = 0; i < 4; ++i) {
        drk_[4 * nr_ + i] = rk_[i];  // last decrypt round key = first encrypt key
    }
}

/* ============================================================
 *  Init
 * ============================================================ */
bool AESContext::init(const uint8_t* key, int key_bits) {
    switch (key_bits) {
        case 128: nk_ = 4; nr_ = 10; break;
        case 192: nk_ = 6; nr_ = 12; break;
        case 256: nk_ = 8; nr_ = 14; break;
        default: return false;
    }
    key_expansion(key);
    compute_decrypt_keys();
    return true;
}

/* ============================================================
 *  Encrypt Block (T-table based)
 * ============================================================ */
void AESContext::encrypt_block(const uint8_t* in, uint8_t* out) const {
    // Load input as 4 big-endian 32-bit words and XOR with first round key
    uint32_t s0 = load_be32(in)      ^ rk_[0];
    uint32_t s1 = load_be32(in + 4)  ^ rk_[1];
    uint32_t s2 = load_be32(in + 8)  ^ rk_[2];
    uint32_t s3 = load_be32(in + 12) ^ rk_[3];

    uint32_t t0 = s0, t1 = s1, t2 = s2, t3 = s3;

    // Rounds 1 to Nr-1: T-table lookup
    for (int r = 1; r < nr_; ++r) {
        t0 = TT.Te0[(s0 >> 24)]       ^ TT.Te1[(s1 >> 16) & 0xff] ^
             TT.Te2[(s2 >> 8) & 0xff] ^ TT.Te3[s3 & 0xff]         ^ rk_[4*r];
        t1 = TT.Te0[(s1 >> 24)]       ^ TT.Te1[(s2 >> 16) & 0xff] ^
             TT.Te2[(s3 >> 8) & 0xff] ^ TT.Te3[s0 & 0xff]         ^ rk_[4*r+1];
        t2 = TT.Te0[(s2 >> 24)]       ^ TT.Te1[(s3 >> 16) & 0xff] ^
             TT.Te2[(s0 >> 8) & 0xff] ^ TT.Te3[s1 & 0xff]         ^ rk_[4*r+2];
        t3 = TT.Te0[(s3 >> 24)]       ^ TT.Te1[(s0 >> 16) & 0xff] ^
             TT.Te2[(s1 >> 8) & 0xff] ^ TT.Te3[s2 & 0xff]         ^ rk_[4*r+3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
    s0 = (static_cast<uint32_t>(SBOX[t0 >> 24]) << 24)       |
         (static_cast<uint32_t>(SBOX[(t1 >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(SBOX[(t2 >> 8) & 0xff]) << 8)   |
         static_cast<uint32_t>(SBOX[t3 & 0xff]);
    s1 = (static_cast<uint32_t>(SBOX[t1 >> 24]) << 24)       |
         (static_cast<uint32_t>(SBOX[(t2 >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(SBOX[(t3 >> 8) & 0xff]) << 8)   |
         static_cast<uint32_t>(SBOX[t0 & 0xff]);
    s2 = (static_cast<uint32_t>(SBOX[t2 >> 24]) << 24)       |
         (static_cast<uint32_t>(SBOX[(t3 >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(SBOX[(t0 >> 8) & 0xff]) << 8)   |
         static_cast<uint32_t>(SBOX[t1 & 0xff]);
    s3 = (static_cast<uint32_t>(SBOX[t3 >> 24]) << 24)       |
         (static_cast<uint32_t>(SBOX[(t0 >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(SBOX[(t1 >> 8) & 0xff]) << 8)   |
         static_cast<uint32_t>(SBOX[t2 & 0xff]);

    store_be32(out,      s0 ^ rk_[4*nr_]);
    store_be32(out + 4,  s1 ^ rk_[4*nr_+1]);
    store_be32(out + 8,  s2 ^ rk_[4*nr_+2]);
    store_be32(out + 12, s3 ^ rk_[4*nr_+3]);
}

/* ============================================================
 *  Decrypt Block (Equivalent Inverse Cipher, T-table based)
 * ============================================================ */
void AESContext::decrypt_block(const uint8_t* in, uint8_t* out) const {
    uint32_t s0 = load_be32(in)      ^ drk_[0];
    uint32_t s1 = load_be32(in + 4)  ^ drk_[1];
    uint32_t s2 = load_be32(in + 8)  ^ drk_[2];
    uint32_t s3 = load_be32(in + 12) ^ drk_[3];

    uint32_t t0 = s0, t1 = s1, t2 = s2, t3 = s3;

    for (int r = 1; r < nr_; ++r) {
        t0 = TT.Td0[(s0 >> 24)]       ^ TT.Td1[(s3 >> 16) & 0xff] ^
             TT.Td2[(s2 >> 8) & 0xff] ^ TT.Td3[s1 & 0xff]         ^ drk_[4*r];
        t1 = TT.Td0[(s1 >> 24)]       ^ TT.Td1[(s0 >> 16) & 0xff] ^
             TT.Td2[(s3 >> 8) & 0xff] ^ TT.Td3[s2 & 0xff]         ^ drk_[4*r+1];
        t2 = TT.Td0[(s2 >> 24)]       ^ TT.Td1[(s1 >> 16) & 0xff] ^
             TT.Td2[(s0 >> 8) & 0xff] ^ TT.Td3[s3 & 0xff]         ^ drk_[4*r+2];
        t3 = TT.Td0[(s3 >> 24)]       ^ TT.Td1[(s2 >> 16) & 0xff] ^
             TT.Td2[(s1 >> 8) & 0xff] ^ TT.Td3[s0 & 0xff]         ^ drk_[4*r+3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    // Final round: InvSubBytes + InvShiftRows + AddRoundKey (no InvMixColumns)
    s0 = (static_cast<uint32_t>(INV_SBOX[t0 >> 24]) << 24)       |
         (static_cast<uint32_t>(INV_SBOX[(t3 >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(INV_SBOX[(t2 >> 8) & 0xff]) << 8)   |
         static_cast<uint32_t>(INV_SBOX[t1 & 0xff]);
    s1 = (static_cast<uint32_t>(INV_SBOX[t1 >> 24]) << 24)       |
         (static_cast<uint32_t>(INV_SBOX[(t0 >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(INV_SBOX[(t3 >> 8) & 0xff]) << 8)   |
         static_cast<uint32_t>(INV_SBOX[t2 & 0xff]);
    s2 = (static_cast<uint32_t>(INV_SBOX[t2 >> 24]) << 24)       |
         (static_cast<uint32_t>(INV_SBOX[(t1 >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(INV_SBOX[(t0 >> 8) & 0xff]) << 8)   |
         static_cast<uint32_t>(INV_SBOX[t3 & 0xff]);
    s3 = (static_cast<uint32_t>(INV_SBOX[t3 >> 24]) << 24)       |
         (static_cast<uint32_t>(INV_SBOX[(t2 >> 16) & 0xff]) << 16) |
         (static_cast<uint32_t>(INV_SBOX[(t1 >> 8) & 0xff]) << 8)   |
         static_cast<uint32_t>(INV_SBOX[t0 & 0xff]);

    store_be32(out,      s0 ^ drk_[4*nr_]);
    store_be32(out + 4,  s1 ^ drk_[4*nr_+1]);
    store_be32(out + 8,  s2 ^ drk_[4*nr_+2]);
    store_be32(out + 12, s3 ^ drk_[4*nr_+3]);
}

/* ============================================================
 *  Legacy AES class (backward compatible)
 * ============================================================ */
AES::AES() {}

AES::AES(const uint8_t* key, int key_bits) {
    if (!ctx_.init(key, key_bits)) {
        throw std::invalid_argument("Invalid AES key length. Use 128, 192, or 256 bits.");
    }
}

void AES::encrypt(const uint8_t* input, uint8_t* output) const {
    ctx_.encrypt_block(input, output);
}

void AES::decrypt(const uint8_t* input, uint8_t* output) const {
    ctx_.decrypt_block(input, output);
}

int AES::getNumRounds() const {
    return ctx_.rounds();
}

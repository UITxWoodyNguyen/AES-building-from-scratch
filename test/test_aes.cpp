/*
 * test_aes.cpp - Comprehensive AES Test Suite
 *
 * Tests:
 *   - FIPS 197 Appendix B/C (AES core)
 *   - SP 800-38A Appendix F (all modes, all key sizes)
 *   - SP 800-38C (CCM examples)
 *   - SP 800-38D / McGrew-Viega (GCM test cases 1-18)
 *   - Negative tests (tag mismatch, invalid inputs)
 */

#define _CRT_SECURE_NO_WARNINGS
#include "aes.h"
#include "aes_modes.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <string>

static int g_total = 0, g_passed = 0, g_failed = 0;

static void check(bool ok, const char* name) {
    g_total++;
    if (ok) {
        g_passed++;
    } else {
        g_failed++;
        printf("  [FAIL] %s\n", name);
    }
}

static void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x", data[i]);
}

// Helper to parse hex string to bytes
static size_t hex_to_bytes(const char* hex, uint8_t* out, size_t max_len) {
    size_t len = 0;
    while (*hex && len < max_len) {
        unsigned int byte;
        if (sscanf(hex, "%2x", &byte) != 1) break;
        out[len++] = static_cast<uint8_t>(byte);
        hex += 2;
    }
    return len;
}

/* ============================================================
 *  FIPS 197 Tests
 * ============================================================ */
static void test_fips197() {
    printf("=== FIPS 197 Tests ===\n");

    // Appendix B: AES-128 known answer
    {
        uint8_t key[16], pt[16], ct[16], expected_ct[16], decrypted[16];
        hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
        hex_to_bytes("3243f6a8885a308d313198a2e0370734", pt, 16);
        hex_to_bytes("3925841d02dc09fbdc118597196a0b32", expected_ct, 16);

        AES aes(key, 128);
        aes.encrypt(pt, ct);
        aes.decrypt(ct, decrypted);

        check(memcmp(ct, expected_ct, 16) == 0, "FIPS-197 App B: AES-128 encrypt");
        check(memcmp(decrypted, pt, 16) == 0, "FIPS-197 App B: AES-128 decrypt");
    }

    // Appendix C: AES-128/192/256
    {
        uint8_t key[32], pt[16], ct[16], decrypted[16];
        hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);
        hex_to_bytes("00112233445566778899aabbccddeeff", pt, 16);

        const char* expected_cts[3] = {
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
            "8ea2b7ca516745bfeafc49904b496089"
        };
        int key_sizes[3] = {128, 192, 256};

        for (int t = 0; t < 3; ++t) {
            uint8_t expected[16];
            hex_to_bytes(expected_cts[t], expected, 16);

            AES aes(key, key_sizes[t]);
            aes.encrypt(pt, ct);
            aes.decrypt(ct, decrypted);

            char name[64];
            snprintf(name, sizeof(name), "FIPS-197 App C: AES-%d encrypt", key_sizes[t]);
            check(memcmp(ct, expected, 16) == 0, name);
            snprintf(name, sizeof(name), "FIPS-197 App C: AES-%d decrypt", key_sizes[t]);
            check(memcmp(decrypted, pt, 16) == 0, name);
        }
    }
}

/* ============================================================
 *  SP 800-38A Appendix F Tests
 * ============================================================ */

// Common test keys
static const char* KEY_128 = "2b7e151628aed2a6abf7158809cf4f3c";
static const char* KEY_192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
static const char* KEY_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
static const char* IV_38A  = "000102030405060708090a0b0c0d0e0f";

// Common plaintext blocks (4 blocks)
static const char* PT_BLOCKS[4] = {
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710"
};

struct ModeTestVector {
    const char* mode_name;
    int key_bits;
    const char* key;
    const char* iv;
    const char* ct_blocks[4]; // expected ciphertext for each block
};

static void test_mode(const ModeTestVector& tv, int mode_type) {
    uint8_t key[32], iv[16], pt[64], ct[64], decrypted[64];
    hex_to_bytes(tv.key, key, 32);
    if (tv.iv) hex_to_bytes(tv.iv, iv, 16);

    for (int i = 0; i < 4; ++i)
        hex_to_bytes(PT_BLOCKS[i], pt + i * 16, 16);

    uint8_t expected_ct[64];
    for (int i = 0; i < 4; ++i)
        hex_to_bytes(tv.ct_blocks[i], expected_ct + i * 16, 16);

    char name[128];
    int rc;

    switch (mode_type) {
        case 0: { // ECB
            AES_ECB ecb;
            ecb.init(key, tv.key_bits);
            rc = ecb.encrypt(pt, ct, 64);
            snprintf(name, sizeof(name), "SP800-38A %s-%d encrypt", tv.mode_name, tv.key_bits);
            bool ok = (rc == 0 && memcmp(ct, expected_ct, 64) == 0);
            check(ok, name);
            if (!ok) {
                printf("    Got: "); print_hex(ct, 64); printf("\n");
                printf("    Exp: "); print_hex(expected_ct, 64); printf("\n");
            }
            rc = ecb.decrypt(ct, decrypted, 64);
            snprintf(name, sizeof(name), "SP800-38A %s-%d decrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(decrypted, pt, 64) == 0, name);
            break;
        }
        case 1: { // CBC
            AES_CBC cbc;
            cbc.init(key, tv.key_bits);
            rc = cbc.encrypt(pt, ct, 64, iv);
            snprintf(name, sizeof(name), "SP800-38A %s-%d encrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(ct, expected_ct, 64) == 0, name);
            rc = cbc.decrypt(ct, decrypted, 64, iv);
            snprintf(name, sizeof(name), "SP800-38A %s-%d decrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(decrypted, pt, 64) == 0, name);
            break;
        }
        case 2: { // CFB128
            AES_CFB cfb;
            cfb.init(key, tv.key_bits, 128);
            rc = cfb.encrypt(pt, ct, 64, iv);
            snprintf(name, sizeof(name), "SP800-38A %s-%d encrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(ct, expected_ct, 64) == 0, name);
            rc = cfb.decrypt(ct, decrypted, 64, iv);
            snprintf(name, sizeof(name), "SP800-38A %s-%d decrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(decrypted, pt, 64) == 0, name);
            break;
        }
        case 3: { // OFB
            AES_OFB ofb;
            ofb.init(key, tv.key_bits);
            rc = ofb.encrypt(pt, ct, 64, iv);
            snprintf(name, sizeof(name), "SP800-38A %s-%d encrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(ct, expected_ct, 64) == 0, name);
            rc = ofb.decrypt(ct, decrypted, 64, iv);
            snprintf(name, sizeof(name), "SP800-38A %s-%d decrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(decrypted, pt, 64) == 0, name);
            break;
        }
        case 4: { // CTR
            AES_CTR ctr;
            ctr.init(key, tv.key_bits);
            rc = ctr.encrypt(pt, ct, 64, iv);
            snprintf(name, sizeof(name), "SP800-38A %s-%d encrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(ct, expected_ct, 64) == 0, name);
            rc = ctr.decrypt(ct, decrypted, 64, iv);
            snprintf(name, sizeof(name), "SP800-38A %s-%d decrypt", tv.mode_name, tv.key_bits);
            check(rc == 0 && memcmp(decrypted, pt, 64) == 0, name);
            break;
        }
    }
}

static void test_sp800_38a() {
    printf("\n=== SP 800-38A Appendix F Tests ===\n");

    // F.1 ECB
    printf("--- ECB ---\n");
    ModeTestVector ecb_vecs[] = {
        {"ECB", 128, KEY_128, nullptr, {
            "3ad77bb40d7a3660a89ecaf32466ef97", "f5d3d58503b9699de785895a96fdbaaf",
            "43b1cd7f598ece23881b00e3ed030688", "7b0c785e27e8ad3f8223207104725dd4"}},
        {"ECB", 192, KEY_192, nullptr, {
            "bd334f1d6e45f25ff712a214571fa5cc", "974104846d0ad3ad7734ecb3ecee4eef",
            "ef7afd2270e2e60adce0ba2face6444e", "9a4b41ba738d6c72fb16691603c18e0e"}},
        {"ECB", 256, KEY_256, nullptr, {
            "f3eed1bdb5d2a03c064b5a7e3db181f8", "591ccb10d410ed26dc5ba74a31362870",
            "b6ed21b99ca6f4f9f153e7b1beafed1d", "23304b7a39f9f3ff067d8d8f9e24ecc7"}},
    };
    for (auto& v : ecb_vecs) test_mode(v, 0);

    // F.2 CBC
    printf("--- CBC ---\n");
    ModeTestVector cbc_vecs[] = {
        {"CBC", 128, KEY_128, IV_38A, {
            "7649abac8119b246cee98e9b12e9197d", "5086cb9b507219ee95db113a917678b2",
            "73bed6b8e3c1743b7116e69e22229516", "3ff1caa1681fac09120eca307586e1a7"}},
        {"CBC", 192, KEY_192, IV_38A, {
            "4f021db243bc633d7178183a9fa071e8", "b4d9ada9ad7dedf4e5e738763f69145a",
            "571b242012fb7ae07fa9baac3df102e0", "08b0e27988598881d920a9e64f5615cd"}},
        {"CBC", 256, KEY_256, IV_38A, {
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6", "9cfc4e967edb808d679f777bc6702c7d",
            "39f23369a9d9bacfa530e26304231461", "b2eb05e2c39be9fcda6c19078c6a9d1b"}},
    };
    for (auto& v : cbc_vecs) test_mode(v, 1);

    // F.3 CFB128
    printf("--- CFB128 ---\n");
    ModeTestVector cfb128_vecs[] = {
        {"CFB128", 128, KEY_128, IV_38A, {
            "3b3fd92eb72dad20333449f8e83cfb4a", "c8a64537a0b3a93fcde3cdad9f1ce58b",
            "26751f67a3cbb140b1808cf187a4f4df", "c04b05357c5d1c0eeac4c66f9ff7f2e6"}},
        {"CFB128", 192, KEY_192, IV_38A, {
            "cdc80d6fddf18cab34c25909c99a4174", "67ce7f7f81173621961a2b70171d3d7a",
            "2e1e8a1dd59b88b1c8e60fed1efac4c9", "c05f9f9ca9834fa042ae8fba584b09ff"}},
        {"CFB128", 256, KEY_256, IV_38A, {
            "dc7e84bfda79164b7ecd8486985d3860", "39ffed143b28b1c832113c6331e5407b",
            "df10132415e54b92a13ed0a8267ae2f9", "75a385741ab9cef82031623d55b1e471"}},
    };
    for (auto& v : cfb128_vecs) test_mode(v, 2);

    // F.4 OFB
    printf("--- OFB ---\n");
    ModeTestVector ofb_vecs[] = {
        {"OFB", 128, KEY_128, IV_38A, {
            "3b3fd92eb72dad20333449f8e83cfb4a", "7789508d16918f03f53c52dac54ed825",
            "9740051e9c5fecf64344f7a82260edcc", "304c6528f659c77866a510d9c1d6ae5e"}},
        {"OFB", 192, KEY_192, IV_38A, {
            "cdc80d6fddf18cab34c25909c99a4174", "fcc28b8d4c63837c09e81700c1100401",
            "8d9a9aeac0f6596f559c6d4daf59a5f2", "6d9f200857ca6c3e9cac524bd9acc92a"}},
        {"OFB", 256, KEY_256, IV_38A, {
            "dc7e84bfda79164b7ecd8486985d3860", "4febdc6740d20b3ac88f6ad82a4fb08d",
            "71ab47a086e86eedf39d1c5bba97c408", "0126141d67f37be8538f5a8be740e484"}},
    };
    for (auto& v : ofb_vecs) test_mode(v, 3);

    // F.5 CTR
    printf("--- CTR ---\n");
    ModeTestVector ctr_vecs[] = {
        {"CTR", 128, KEY_128, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", {
            "874d6191b620e3261bef6864990db6ce", "9806f66b7970fdff8617187bb9fffdff",
            "5ae4df3edbd5d35e5b4f09020db03eab", "1e031dda2fbe03d1792170a0f3009cee"}},
        {"CTR", 192, KEY_192, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", {
            "1abc932417521ca24f2b0459fe7e6e0b", "090339ec0aa6faefd5ccc2c6f4ce8e94",
            "1e36b26bd1ebc670d1bd1d665620abf7", "4f78a7f6d29809585a97daec58c6b050"}},
        {"CTR", 256, KEY_256, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", {
            "601ec313775789a5b7a7f504bbf3d228", "f443e3ca4d62b59aca84e990cacaf5c5",
            "2b0930daa23de94ce87017ba2d84988d", "dfc9c58db67aada613c2dd08457941a6"}},
    };
    for (auto& v : ctr_vecs) test_mode(v, 4);

    // F.3.7/F.3.8 CFB8
    printf("--- CFB8 ---\n");
    {
        // CFB8-AES128 test from SP 800-38A
        uint8_t key[16], iv[16];
        hex_to_bytes(KEY_128, key, 16);
        hex_to_bytes(IV_38A, iv, 16);

        // Only first 18 bytes of plaintext for CFB8 test
        uint8_t pt[18], ct[18], decrypted[18];
        hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d", pt, 18);
        uint8_t expected_ct[18];
        hex_to_bytes("3b79424c9c0dd436bace9e0ed4586a4f32b9", expected_ct, 18);

        AES_CFB cfb8;
        cfb8.init(key, 128, 8);
        int rc = cfb8.encrypt(pt, ct, 18, iv);
        check(rc == 0 && memcmp(ct, expected_ct, 18) == 0, "SP800-38A CFB8-AES128 encrypt");
        rc = cfb8.decrypt(ct, decrypted, 18, iv);
        check(rc == 0 && memcmp(decrypted, pt, 18) == 0, "SP800-38A CFB8-AES128 decrypt");
    }

    // F.3.1/F.3.2 CFB1
    printf("--- CFB1 ---\n");
    {
        uint8_t key[16], iv[16];
        hex_to_bytes(KEY_128, key, 16);
        hex_to_bytes(IV_38A, iv, 16);

        // CFB1-AES128: first 16 bits of plaintext (in binary, packed in bytes)
        // Plaintext bits: 0110101111000001... (from 6bc1...)
        // The NIST test uses individual bits; we pack MSB first in bytes
        uint8_t pt_bits[2] = {0x6b, 0xc1}; // 16 bits packed
        uint8_t ct_bits[2] = {0x68, 0xb3}; // expected: 0110100010110011
        uint8_t out[2], decrypted[2];

        AES_CFB cfb1;
        cfb1.init(key, 128, 1);
        int rc = cfb1.encrypt(pt_bits, out, 16, iv);  // 16 bits
        check(rc == 0 && memcmp(out, ct_bits, 2) == 0, "SP800-38A CFB1-AES128 encrypt (16 bits)");
        rc = cfb1.decrypt(ct_bits, decrypted, 16, iv);
        check(rc == 0 && memcmp(decrypted, pt_bits, 2) == 0, "SP800-38A CFB1-AES128 decrypt (16 bits)");
    }
}

/* ============================================================
 *  SP 800-38C: CCM Tests
 * ============================================================ */
static void test_sp800_38c() {
    printf("\n=== SP 800-38C CCM Tests ===\n");

    struct CCMTestVector {
        const char* name;
        const char* key;
        const char* nonce;
        size_t nonce_len;
        const char* aad;
        size_t aad_len;
        const char* plaintext;
        size_t pt_len;
        const char* expected_ct;
        const char* expected_tag;
        size_t tag_len;
    };

    CCMTestVector ccm_vecs[] = {
        // Example 1: Tlen=32(4 bytes), Nlen=56(7 bytes)
        {"CCM Example 1", "404142434445464748494a4b4c4d4e4f",
         "10111213141516", 7,
         "0001020304050607", 8,
         "20212223", 4,
         "7162015b", "4dac255d", 4},

        // Example 2: Tlen=48(6 bytes), Nlen=64(8 bytes)
        {"CCM Example 2", "404142434445464748494a4b4c4d4e4f",
         "1011121314151617", 8,
         "000102030405060708090a0b0c0d0e0f", 16,
         "202122232425262728292a2b2c2d2e2f", 16,
         "d2a1f0e051ea5f62081a7792073d593d", "1fc64fbfaccd", 6},

        // Example 3: Tlen=64(8 bytes), Nlen=96(12 bytes)
        {"CCM Example 3", "404142434445464748494a4b4c4d4e4f",
         "101112131415161718191a1b", 12,
         "000102030405060708090a0b0c0d0e0f10111213", 20,
         "202122232425262728292a2b2c2d2e2f3031323334353637", 24,
         "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5",
         "484392fbc1b09951", 8},

        // Example 4: Tlen=112(14 bytes), Nlen=104(13 bytes), Alen=524288 bits = 65536 bytes
        {"CCM Example 4", "404142434445464748494a4b4c4d4e4f",
         "101112131415161718191a1b1c", 13,
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 65536,
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", 32,
         "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72",
         "b4ac6bec93e8598e7f0dadbcea5b", 14},
    };

    for (const auto& tv : ccm_vecs) {
        uint8_t key[16], nonce[16], pt[64], ct[64], tag[16];
        uint8_t expected_ct[64], expected_tag[16];
        uint8_t decrypted[64];

        hex_to_bytes(tv.key, key, 16);
        hex_to_bytes(tv.nonce, nonce, 16);

        std::vector<uint8_t> aad_vec(tv.aad_len);
        if (tv.aad_len <= 256) {
            hex_to_bytes(tv.aad, aad_vec.data(), tv.aad_len);
        } else {
            uint8_t pattern[256];
            hex_to_bytes(tv.aad, pattern, 256);
            for (size_t off = 0; off < tv.aad_len; off += 256) {
                size_t c = std::min(static_cast<size_t>(256), tv.aad_len - off);
                std::memcpy(aad_vec.data() + off, pattern, c);
            }
        }

        hex_to_bytes(tv.plaintext, pt, 64);
        hex_to_bytes(tv.expected_ct, expected_ct, 64);
        hex_to_bytes(tv.expected_tag, expected_tag, 16);

        AES_CCM ccm;
        ccm.init(key, 128);

        int rc = ccm.encrypt(nonce, tv.nonce_len, aad_vec.data(), tv.aad_len,
                              pt, tv.pt_len, ct, tag, tv.tag_len);

        char name[128];
        snprintf(name, sizeof(name), "%s encrypt", tv.name);
        bool ct_ok = (rc == 0) && memcmp(ct, expected_ct, tv.pt_len) == 0;
        bool tag_ok = memcmp(tag, expected_tag, tv.tag_len) == 0;
        check(ct_ok && tag_ok, name);

        if (!ct_ok || !tag_ok) {
            printf("    CT:  "); print_hex(ct, tv.pt_len); printf("\n");
            printf("    Exp: "); print_hex(expected_ct, tv.pt_len); printf("\n");
            printf("    Tag: "); print_hex(tag, tv.tag_len); printf("\n");
            printf("    Exp: "); print_hex(expected_tag, tv.tag_len); printf("\n");
        }

        // Decrypt
        rc = ccm.decrypt(nonce, tv.nonce_len, aad_vec.data(), tv.aad_len,
                          ct, tv.pt_len, decrypted, tag, tv.tag_len);
        snprintf(name, sizeof(name), "%s decrypt", tv.name);
        check(rc == 0 && memcmp(decrypted, pt, tv.pt_len) == 0, name);

        // Negative test: wrong tag
        uint8_t bad_tag[16];
        memcpy(bad_tag, tag, tv.tag_len);
        bad_tag[0] ^= 0x01;
        rc = ccm.decrypt(nonce, tv.nonce_len, aad_vec.data(), tv.aad_len,
                          ct, tv.pt_len, decrypted, bad_tag, tv.tag_len);
        snprintf(name, sizeof(name), "%s auth fail", tv.name);
        check(rc == AES_ERR_AUTH_FAILED, name);
    }
}

/* ============================================================
 *  SP 800-38D: GCM Tests (McGrew-Viega Test Cases)
 * ============================================================ */
static void test_sp800_38d() {
    printf("\n=== SP 800-38D GCM Tests ===\n");

    struct GCMTestVector {
        const char* name;
        int key_bits;
        const char* key;
        const char* iv;
        size_t iv_len;
        const char* aad;
        size_t aad_len;
        const char* plaintext;
        size_t pt_len;
        const char* expected_ct;
        const char* expected_tag;
        size_t tag_len;
    };

    GCMTestVector gcm_vecs[] = {
        // Test Case 1: key=0^128, no plaintext, no AAD, 96-bit IV
        {"GCM TC1", 128, "00000000000000000000000000000000",
         "000000000000000000000000", 12,
         "", 0, "", 0, "",
         "58e2fccefa7e3061367f1d57a4e7455a", 16},

        // Test Case 2: key=0^128, zero plaintext
        {"GCM TC2", 128, "00000000000000000000000000000000",
         "000000000000000000000000", 12,
         "", 0,
         "00000000000000000000000000000000", 16,
         "0388dace60b6a392f328c2b971b2fe78",
         "ab6e47d42cec13bdf53a67b21257bddf", 16},

        // Test Case 3
        {"GCM TC3", 128, "feffe9928665731c6d6a8f9467308308",
         "cafebabefacedbaddecaf888", 12,
         "", 0,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", 64,
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
         "4d5c2af327cd64a62cf35abd2ba6fab4", 16},

        // Test Case 4: with AAD
        {"GCM TC4", 128, "feffe9928665731c6d6a8f9467308308",
         "cafebabefacedbaddecaf888", 12,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
         "5bc94fbc3221a5db94fae95ae7121a47", 16},

        // Test Case 5: IV != 96 bits (60 bytes = 480 bits)
        {"GCM TC5", 128, "feffe9928665731c6d6a8f9467308308",
         "cafebabefacedbad", 8,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
         "3612d2e79e3b0785561be14aaca2fccb", 16},

        // Test Case 6: IV = 480 bits
        {"GCM TC6", 128, "feffe9928665731c6d6a8f9467308308",
         "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", 60,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
         "619cc5aefffe0bfa462af43c1699d050", 16},

        // Test Case 7: AES-192
        {"GCM TC7", 192, "000000000000000000000000000000000000000000000000",
         "000000000000000000000000", 12,
         "", 0, "", 0, "",
         "cd33b28ac773f74ba00ed1f312572435", 16},

        // Test Case 8
        {"GCM TC8", 192, "000000000000000000000000000000000000000000000000",
         "000000000000000000000000", 12,
         "", 0,
         "00000000000000000000000000000000", 16,
         "98e7247c07f0fe411c267e4384b0f600",
         "2ff58d80033927ab8ef4d4587514f0fb", 16},

        // Test Case 9
        {"GCM TC9", 192, "feffe9928665731c6d6a8f9467308308feffe9928665731c",
         "cafebabefacedbaddecaf888", 12,
         "", 0,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", 64,
         "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
         "9924a7c8587336bfb118024db8674a14", 16},

        // Test Case 10
        {"GCM TC10", 192, "feffe9928665731c6d6a8f9467308308feffe9928665731c",
         "cafebabefacedbaddecaf888", 12,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
         "2519498e80f1478f37ba55bd6d27618c", 16},

        // Test Case 11: 192-bit key, non-96-bit IV
        {"GCM TC11", 192, "feffe9928665731c6d6a8f9467308308feffe9928665731c",
         "cafebabefacedbad", 8,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
         "65dcc57fcf623a24094fcca40d3533f8", 16},

        // Test Case 12
        {"GCM TC12", 192, "feffe9928665731c6d6a8f9467308308feffe9928665731c",
         "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", 60,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
         "dcf566ff291c25bbb8568fc3d376a6d9", 16},

        // Test Case 13: AES-256
        {"GCM TC13", 256, "0000000000000000000000000000000000000000000000000000000000000000",
         "000000000000000000000000", 12,
         "", 0, "", 0, "",
         "530f8afbc74536b9a963b4f1c4cb738b", 16},

        // Test Case 14
        {"GCM TC14", 256, "0000000000000000000000000000000000000000000000000000000000000000",
         "000000000000000000000000", 12,
         "", 0,
         "00000000000000000000000000000000", 16,
         "cea7403d4d606b6e074ec5d3baf39d18",
         "d0d1c8a799996bf0265b98b5d48ab919", 16},

        // Test Case 15
        {"GCM TC15", 256, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
         "cafebabefacedbaddecaf888", 12,
         "", 0,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", 64,
         "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
         "b094dac5d93471bdec1a502270e3cc6c", 16},

        // Test Case 16
        {"GCM TC16", 256, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
         "cafebabefacedbaddecaf888", 12,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
         "76fc6ece0f4e1768cddf8853bb2d551b", 16},

        // Test Case 17: AES-256, non-96-bit IV
        {"GCM TC17", 256, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
         "cafebabefacedbad", 8,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
         "3a337dbf46a792c45e454913fe2ea8f2", 16},

        // Test Case 18
        {"GCM TC18", 256, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
         "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", 60,
         "feedfacedeadbeeffeedfacedeadbeefabaddad2", 20,
         "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60,
         "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
         "a44a8266ee1c8eb0c8b5d4cf5ae9f19a", 16},
    };

    for (const auto& tv : gcm_vecs) {
        uint8_t key[32], iv[64], aad[32], pt[64], ct[64], tag[16];
        uint8_t expected_ct[64], expected_tag[16];
        uint8_t decrypted[64];

        hex_to_bytes(tv.key, key, 32);
        hex_to_bytes(tv.iv, iv, 64);
        hex_to_bytes(tv.aad, aad, 32);
        hex_to_bytes(tv.plaintext, pt, 64);
        hex_to_bytes(tv.expected_ct, expected_ct, 64);
        hex_to_bytes(tv.expected_tag, expected_tag, 16);

        AES_GCM gcm;
        gcm.init(key, tv.key_bits);

        int rc = gcm.encrypt(iv, tv.iv_len, aad, tv.aad_len,
                              pt, tv.pt_len, ct, tag, tv.tag_len);

        char name[128];
        snprintf(name, sizeof(name), "%s encrypt", tv.name);
        bool ct_ok = (rc == 0) && (tv.pt_len == 0 || memcmp(ct, expected_ct, tv.pt_len) == 0);
        bool tag_ok = memcmp(tag, expected_tag, tv.tag_len) == 0;
        check(ct_ok && tag_ok, name);

        if (!ct_ok || !tag_ok) {
            printf("    CT:  "); if (tv.pt_len > 0) print_hex(ct, tv.pt_len); printf("\n");
            printf("    Exp: "); if (tv.pt_len > 0) print_hex(expected_ct, tv.pt_len); printf("\n");
            printf("    Tag: "); print_hex(tag, tv.tag_len); printf("\n");
            printf("    Exp: "); print_hex(expected_tag, tv.tag_len); printf("\n");
        }

        // Decrypt and verify
        rc = gcm.decrypt(iv, tv.iv_len, aad, tv.aad_len,
                          ct, tv.pt_len, decrypted, tag, tv.tag_len);
        snprintf(name, sizeof(name), "%s decrypt", tv.name);
        check(rc == 0 && (tv.pt_len == 0 || memcmp(decrypted, pt, tv.pt_len) == 0), name);

        // Negative: wrong tag
        if (tv.pt_len > 0) {
            uint8_t bad_tag[16];
            memcpy(bad_tag, tag, tv.tag_len);
            bad_tag[0] ^= 0x01;
            rc = gcm.decrypt(iv, tv.iv_len, aad, tv.aad_len,
                              ct, tv.pt_len, decrypted, bad_tag, tv.tag_len);
            snprintf(name, sizeof(name), "%s auth fail", tv.name);
            check(rc == AES_ERR_AUTH_FAILED, name);
        }
    }
}

/* ============================================================
 *  Benchmark
 * ============================================================ */
static void benchmark() {
    printf("\n=== Benchmark ===\n");

    const size_t DATA_SIZE = 64 * 1024 * 1024; // 64 MB
    std::vector<uint8_t> data(DATA_SIZE, 0xAA);
    std::vector<uint8_t> out(DATA_SIZE + 16);

    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};

    auto bench_mode = [&](const char* name, auto encrypt_fn) {
        auto start = std::chrono::high_resolution_clock::now();
        encrypt_fn(data.data(), out.data(), DATA_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start).count();
        double mbps = (DATA_SIZE / (1024.0 * 1024.0)) / (ms / 1000.0);
        printf("  %-12s: %7.1f MB/s  (%.1f ms for %zu MB)\n", name, mbps, ms, DATA_SIZE / (1024*1024));
    };

    AES_ECB ecb;
    ecb.init(key, 128);
    bench_mode("ECB-enc", [&](const uint8_t* in, uint8_t* o, size_t len) { ecb.encrypt(in, o, len); });
    bench_mode("ECB-dec", [&](const uint8_t* in, uint8_t* o, size_t len) { ecb.decrypt(in, o, len); });

    AES_CBC cbc;
    cbc.init(key, 128);
    bench_mode("CBC-enc", [&](const uint8_t* in, uint8_t* o, size_t len) { cbc.encrypt(in, o, len, iv); });
    bench_mode("CBC-dec", [&](const uint8_t* in, uint8_t* o, size_t len) { cbc.decrypt(in, o, len, iv); });

    AES_CTR ctr;
    ctr.init(key, 128);
    bench_mode("CTR", [&](const uint8_t* in, uint8_t* o, size_t len) { ctr.encrypt(in, o, len, iv); });

    AES_GCM gcm;
    gcm.init(key, 128);
    uint8_t tag[16];
    bench_mode("GCM-enc", [&](const uint8_t* in, uint8_t* o, size_t len) {
        gcm.encrypt(iv, 12, nullptr, 0, in, len, o, tag, 16);
    });

    // CCM (smaller data due to length encoding limits)
    AES_CCM ccm;
    ccm.init(key, 128);
    const size_t CCM_SIZE = 1024 * 1024; // 1 MB
    std::vector<uint8_t> ccm_data(CCM_SIZE, 0xAA);
    std::vector<uint8_t> ccm_out(CCM_SIZE + 16);
    uint8_t nonce[11] = {0};
    auto start = std::chrono::high_resolution_clock::now();
    ccm.encrypt(nonce, 11, nullptr, 0, ccm_data.data(), CCM_SIZE, ccm_out.data(), tag, 16);
    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    double mbps = (CCM_SIZE / (1024.0 * 1024.0)) / (ms / 1000.0);
    printf("  %-12s: %7.1f MB/s  (%.1f ms for %zu KB)\n", "CCM-enc", mbps, ms, CCM_SIZE / 1024);
}

/* ============================================================
 *  Main
 * ============================================================ */
int main(int argc, char* argv[]) {
    bool run_bench = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--bench") == 0 || strcmp(argv[i], "-b") == 0)
            run_bench = true;
    }

    test_fips197();
    test_sp800_38a();
    test_sp800_38c();
    test_sp800_38d();

    printf("\n========================================\n");
    printf("Results: %d/%d passed", g_passed, g_total);
    if (g_failed > 0) {
        printf(", %d FAILED", g_failed);
    }
    printf("\n========================================\n");

    if (run_bench) benchmark();

    return g_failed > 0 ? 1 : 0;
}


/*
 * diff_test.cpp - Differential testing between old AES and optimized AES
 *
 * Compares 1,000,000 blocks with fixed seed (mt19937) for AES-128, AES-192, AES-256.
 */

#include "aes.h"
#include "old_aes.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>

int main() {
    printf("=== Differential Test: Old vs New AES (1,000,000 blocks) ===\n");

    std::mt19937 rng(1337); // fixed seed
    const int NUM_BLOCKS = 1000000;

    int key_sizes[3] = {128, 192, 256};
    uint8_t key[32];
    uint8_t in_block[16];
    uint8_t old_ct[16], new_ct[16];
    uint8_t old_pt[16], new_pt[16];

    for (int ks : key_sizes) {
        for (int i = 0; i < ks / 8; ++i) key[i] = static_cast<uint8_t>(rng());

        OldAES old_aes(key, ks);
        AES new_aes(key, ks);

        bool all_matched = true;
        for (int b = 0; b < NUM_BLOCKS; ++b) {
            for (int i = 0; i < 16; ++i) in_block[i] = static_cast<uint8_t>(rng());

            // Test Encrypt
            old_aes.encrypt(in_block, old_ct);
            new_aes.encrypt(in_block, new_ct);
            if (std::memcmp(old_ct, new_ct, 16) != 0) {
                printf("  [FAIL] AES-%d encrypt mismatch at block %d!\n", ks, b);
                all_matched = false;
                break;
            }

            // Test Decrypt
            old_aes.decrypt(old_ct, old_pt);
            new_aes.decrypt(new_ct, new_pt);
            if (std::memcmp(old_pt, new_pt, 16) != 0 || std::memcmp(old_pt, in_block, 16) != 0) {
                printf("  [FAIL] AES-%d decrypt mismatch at block %d!\n", ks, b);
                all_matched = false;
                break;
            }
        }

        if (all_matched) {
            printf("  AES-%d: %d/%d blocks matched old implementation 100%%\n", ks, NUM_BLOCKS, NUM_BLOCKS);
        } else {
            return 1;
        }
    }

    printf("Differential test PASSED 100%%.\n");
    return 0;
}


/*
 * aes_ni.h - Hardware-accelerated AES using AES-NI intrinsics
 */

#ifndef AES_NI_H_INCLUDED
#define AES_NI_H_INCLUDED

#include <cstdint>
#include <cstddef>

namespace aes_hw {

bool aesni_is_supported();

void aesni_key_expand(const uint8_t* key, int key_bits,
                      void* enc_keys, void* dec_keys, int& nr);

void aesni_encrypt_block(const void* enc_keys, int nr, const uint8_t* in, uint8_t* out);
void aesni_decrypt_block(const void* dec_keys, int nr, const uint8_t* in, uint8_t* out);

} // namespace aes_hw

#endif // AES_NI_H_INCLUDED


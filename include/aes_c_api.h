/*
 * aes_c_api.h - Pure C API for AES and modes of operation
 *
 * Opaque handle, error codes, no exceptions, safe for ctypes/FFI.
 */

#ifndef AES_C_API_H_INCLUDED
#define AES_C_API_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
  #if defined(AES_BUILDING_SHARED)
    #define AES_EXPORT __declspec(dllexport)
  #elif defined(AES_USING_SHARED)
    #define AES_EXPORT __declspec(dllimport)
  #else
    #define AES_EXPORT
  #endif
#else
  #define AES_EXPORT __attribute__((visibility("default")))
#endif

/* Error codes */
#define AES_STATUS_OK                 0
#define AES_STATUS_ERR_INVALID_KEY   -1
#define AES_STATUS_ERR_INVALID_IV    -2
#define AES_STATUS_ERR_INVALID_INPUT -3
#define AES_STATUS_ERR_AUTH_FAILED   -4
#define AES_STATUS_ERR_INVALID_TAG   -5
#define AES_STATUS_ERR_INVALID_NONCE -6
#define AES_STATUS_ERR_INVALID_PARAM -7
#define AES_STATUS_ERR_BUFFER_SMALL  -8
#define AES_STATUS_ERR_NULL_PTR      -9

/* Opaque context handle */
typedef struct aes_ctx_opaque* aes_ctx_t;

/* Version and Error string */
AES_EXPORT const char* aes_version(void);
AES_EXPORT const char* aes_error_string(int error_code);

/* Context lifecycle */
AES_EXPORT aes_ctx_t aes_ctx_new(void);
AES_EXPORT int aes_ctx_init(aes_ctx_t ctx, const uint8_t* key, int key_bits);
AES_EXPORT void aes_ctx_free(aes_ctx_t ctx);

/* Single block */
AES_EXPORT int aes_encrypt_block(aes_ctx_t ctx, const uint8_t in[16], uint8_t out[16]);
AES_EXPORT int aes_decrypt_block(aes_ctx_t ctx, const uint8_t in[16], uint8_t out[16]);

/* SP 800-38A Modes */
AES_EXPORT int aes_ecb_encrypt(const uint8_t* key, int key_bits,
                               const uint8_t* in, uint8_t* out, size_t len);
AES_EXPORT int aes_ecb_decrypt(const uint8_t* key, int key_bits,
                               const uint8_t* in, uint8_t* out, size_t len);

AES_EXPORT int aes_cbc_encrypt(const uint8_t* key, int key_bits, const uint8_t iv[16],
                               const uint8_t* in, uint8_t* out, size_t len);
AES_EXPORT int aes_cbc_decrypt(const uint8_t* key, int key_bits, const uint8_t iv[16],
                               const uint8_t* in, uint8_t* out, size_t len);

AES_EXPORT int aes_cfb_encrypt(const uint8_t* key, int key_bits, int segment_bits, const uint8_t iv[16],
                               const uint8_t* in, uint8_t* out, size_t len);
AES_EXPORT int aes_cfb_decrypt(const uint8_t* key, int key_bits, int segment_bits, const uint8_t iv[16],
                               const uint8_t* in, uint8_t* out, size_t len);

AES_EXPORT int aes_ofb_encrypt(const uint8_t* key, int key_bits, const uint8_t iv[16],
                               const uint8_t* in, uint8_t* out, size_t len);
AES_EXPORT int aes_ofb_decrypt(const uint8_t* key, int key_bits, const uint8_t iv[16],
                               const uint8_t* in, uint8_t* out, size_t len);

AES_EXPORT int aes_ctr_crypt(const uint8_t* key, int key_bits, const uint8_t counter[16],
                             const uint8_t* in, uint8_t* out, size_t len);

/* SP 800-38C CCM */
AES_EXPORT int aes_ccm_encrypt(const uint8_t* key, int key_bits,
                               const uint8_t* nonce, size_t nonce_len,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t* in, size_t in_len,
                               uint8_t* out, uint8_t* tag, size_t tag_len);
AES_EXPORT int aes_ccm_decrypt(const uint8_t* key, int key_bits,
                               const uint8_t* nonce, size_t nonce_len,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t* in, size_t in_len,
                               uint8_t* out, const uint8_t* tag, size_t tag_len);

/* SP 800-38D GCM */
AES_EXPORT int aes_gcm_encrypt(const uint8_t* key, int key_bits,
                               const uint8_t* iv, size_t iv_len,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t* in, size_t in_len,
                               uint8_t* out, uint8_t* tag, size_t tag_len);
AES_EXPORT int aes_gcm_decrypt(const uint8_t* key, int key_bits,
                               const uint8_t* iv, size_t iv_len,
                               const uint8_t* aad, size_t aad_len,
                               const uint8_t* in, size_t in_len,
                               uint8_t* out, const uint8_t* tag, size_t tag_len);

#ifdef __cplusplus
}
#endif

#endif /* AES_C_API_H_INCLUDED */


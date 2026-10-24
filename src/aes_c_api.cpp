/*
 * aes_c_api.cpp - C API Implementation
 */

#include "aes_c_api.h"
#include "aes.h"
#include "aes_modes.h"
#include <new>

struct aes_ctx_opaque {
    AESContext ctx;
};

const char* aes_version(void) {
    return "AES-Suite 2.0 (FIPS 197, SP 800-38A/C/D)";
}

const char* aes_error_string(int error_code) {
    switch (error_code) {
        case AES_STATUS_OK:                 return "Success";
        case AES_STATUS_ERR_INVALID_KEY:   return "Invalid key or key length";
        case AES_STATUS_ERR_INVALID_IV:    return "Invalid IV or IV length";
        case AES_STATUS_ERR_INVALID_INPUT: return "Invalid input data or length";
        case AES_STATUS_ERR_AUTH_FAILED:   return "Authentication verification failed";
        case AES_STATUS_ERR_INVALID_TAG:   return "Invalid tag length";
        case AES_STATUS_ERR_INVALID_NONCE: return "Invalid nonce length";
        case AES_STATUS_ERR_INVALID_PARAM: return "Invalid parameter";
        case AES_STATUS_ERR_BUFFER_SMALL:  return "Buffer too small";
        case AES_STATUS_ERR_NULL_PTR:      return "Null pointer argument";
        default:                           return "Unknown error";
    }
}

aes_ctx_t aes_ctx_new(void) {
    return new (std::nothrow) aes_ctx_opaque();
}

int aes_ctx_init(aes_ctx_t ctx, const uint8_t* key, int key_bits) {
    if (!ctx || !key) return AES_STATUS_ERR_NULL_PTR;
    return ctx->ctx.init(key, key_bits) ? AES_STATUS_OK : AES_STATUS_ERR_INVALID_KEY;
}

void aes_ctx_free(aes_ctx_t ctx) {
    if (ctx) {
        delete ctx;
    }
}

int aes_encrypt_block(aes_ctx_t ctx, const uint8_t in[16], uint8_t out[16]) {
    if (!ctx || !in || !out) return AES_STATUS_ERR_NULL_PTR;
    ctx->ctx.encrypt_block(in, out);
    return AES_STATUS_OK;
}

int aes_decrypt_block(aes_ctx_t ctx, const uint8_t in[16], uint8_t out[16]) {
    if (!ctx || !in || !out) return AES_STATUS_ERR_NULL_PTR;
    ctx->ctx.decrypt_block(in, out);
    return AES_STATUS_OK;
}

int aes_ecb_encrypt(const uint8_t* key, int key_bits,
                     const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || (!in && len > 0) || (!out && len > 0)) return AES_STATUS_ERR_NULL_PTR;
    AES_ECB ecb;
    int rc = ecb.init(key, key_bits);
    if (rc != 0) return rc;
    return ecb.encrypt(in, out, len);
}

int aes_ecb_decrypt(const uint8_t* key, int key_bits,
                     const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || (!in && len > 0) || (!out && len > 0)) return AES_STATUS_ERR_NULL_PTR;
    AES_ECB ecb;
    int rc = ecb.init(key, key_bits);
    if (rc != 0) return rc;
    return ecb.decrypt(in, out, len);
}

int aes_cbc_encrypt(const uint8_t* key, int key_bits, const uint8_t iv[16],
                     const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || !iv || (!in && len > 0) || (!out && len > 0)) return AES_STATUS_ERR_NULL_PTR;
    AES_CBC cbc;
    int rc = cbc.init(key, key_bits);
    if (rc != 0) return rc;
    return cbc.encrypt(in, out, len, iv);
}

int aes_cbc_decrypt(const uint8_t* key, int key_bits, const uint8_t iv[16],
                     const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || !iv || (!in && len > 0) || (!out && len > 0)) return AES_STATUS_ERR_NULL_PTR;
    AES_CBC cbc;
    int rc = cbc.init(key, key_bits);
    if (rc != 0) return rc;
    return cbc.decrypt(in, out, len, iv);
}

int aes_cfb_encrypt(const uint8_t* key, int key_bits, int segment_bits, const uint8_t iv[16],
                     const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || !iv || (!in && len > 0) || (!out && len > 0)) return AES_STATUS_ERR_NULL_PTR;
    AES_CFB cfb;
    int rc = cfb.init(key, key_bits, segment_bits);
    if (rc != 0) return rc;
    return cfb.encrypt(in, out, len, iv);
}

int aes_cfb_decrypt(const uint8_t* key, int key_bits, int segment_bits, const uint8_t iv[16],
                     const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || !iv || (!in && len > 0) || (!out && len > 0)) return AES_STATUS_ERR_NULL_PTR;
    AES_CFB cfb;
    int rc = cfb.init(key, key_bits, segment_bits);
    if (rc != 0) return rc;
    return cfb.decrypt(in, out, len, iv);
}

int aes_ofb_encrypt(const uint8_t* key, int key_bits, const uint8_t iv[16],
                     const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || !iv || (!in && len > 0) || (!out && len > 0)) return AES_STATUS_ERR_NULL_PTR;
    AES_OFB ofb;
    int rc = ofb.init(key, key_bits);
    if (rc != 0) return rc;
    return ofb.encrypt(in, out, len, iv);
}

int aes_ofb_decrypt(const uint8_t* key, int key_bits, const uint8_t iv[16],
                     const uint8_t* in, uint8_t* out, size_t len) {
    return aes_ofb_encrypt(key, key_bits, iv, in, out, len);
}

int aes_ctr_crypt(const uint8_t* key, int key_bits, const uint8_t counter[16],
                  const uint8_t* in, uint8_t* out, size_t len) {
    if (!key || !counter || (!in && len > 0) || (!out && len > 0)) return AES_STATUS_ERR_NULL_PTR;
    AES_CTR ctr;
    int rc = ctr.init(key, key_bits);
    if (rc != 0) return rc;
    return ctr.encrypt(in, out, len, counter);
}

int aes_ccm_encrypt(const uint8_t* key, int key_bits,
                     const uint8_t* nonce, size_t nonce_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* in, size_t in_len,
                     uint8_t* out, uint8_t* tag, size_t tag_len) {
    if (!key || !nonce || !tag || (!in && in_len > 0) || (!out && in_len > 0))
        return AES_STATUS_ERR_NULL_PTR;
    AES_CCM ccm;
    int rc = ccm.init(key, key_bits);
    if (rc != 0) return rc;
    return ccm.encrypt(nonce, nonce_len, aad, aad_len, in, in_len, out, tag, tag_len);
}

int aes_ccm_decrypt(const uint8_t* key, int key_bits,
                     const uint8_t* nonce, size_t nonce_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* in, size_t in_len,
                     uint8_t* out, const uint8_t* tag, size_t tag_len) {
    if (!key || !nonce || !tag || (!in && in_len > 0) || (!out && in_len > 0))
        return AES_STATUS_ERR_NULL_PTR;
    AES_CCM ccm;
    int rc = ccm.init(key, key_bits);
    if (rc != 0) return rc;
    return ccm.decrypt(nonce, nonce_len, aad, aad_len, in, in_len, out, tag, tag_len);
}

int aes_gcm_encrypt(const uint8_t* key, int key_bits,
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* in, size_t in_len,
                     uint8_t* out, uint8_t* tag, size_t tag_len) {
    if (!key || !iv || !tag || (!in && in_len > 0) || (!out && in_len > 0))
        return AES_STATUS_ERR_NULL_PTR;
    AES_GCM gcm;
    int rc = gcm.init(key, key_bits);
    if (rc != 0) return rc;
    return gcm.encrypt(iv, iv_len, aad, aad_len, in, in_len, out, tag, tag_len);
}

int aes_gcm_decrypt(const uint8_t* key, int key_bits,
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* in, size_t in_len,
                     uint8_t* out, const uint8_t* tag, size_t tag_len) {
    if (!key || !iv || !tag || (!in && in_len > 0) || (!out && in_len > 0))
        return AES_STATUS_ERR_NULL_PTR;
    AES_GCM gcm;
    int rc = gcm.init(key, key_bits);
    if (rc != 0) return rc;
    return gcm.decrypt(iv, iv_len, aad, aad_len, in, in_len, out, tag, tag_len);
}


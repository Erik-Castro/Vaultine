#pragma once

#include <cstddef>
#include <cstdint>

namespace ssm::v1 {

static constexpr size_t AES_GCM_KEY_LEN   = 32;
static constexpr size_t AES_GCM_NONCE_LEN = 12;
static constexpr size_t AES_GCM_TAG_LEN   = 16;

bool aes_gcm_encrypt(
    const unsigned char* plaintext, size_t plaintext_len,
    const unsigned char* key, size_t key_len,
    const unsigned char* nonce, size_t nonce_len,
    const unsigned char* aad, size_t aad_len,
    unsigned char* ciphertext_out,
    unsigned char* tag_out, size_t tag_len);

bool aes_gcm_decrypt(
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* key, size_t key_len,
    const unsigned char* nonce, size_t nonce_len,
    const unsigned char* aad, size_t aad_len,
    const unsigned char* tag, size_t tag_len,
    unsigned char* plaintext_out);

} // namespace ssm::v1

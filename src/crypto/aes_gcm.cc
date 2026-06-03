#include "crypto/aes_gcm.h"

#include <openssl/evp.h>

namespace ssm::v1 {
namespace {

EVP_CIPHER_CTX* acquire_cipher_ctx() {
    thread_local EVP_CIPHER_CTX* ctx = nullptr;
    thread_local bool first = true;
    if (!ctx)
        ctx = EVP_CIPHER_CTX_new();
    if (first)
        first = false;
    else if (ctx)
        EVP_CIPHER_CTX_reset(ctx);
    return ctx;
}

}  // namespace

bool aes_gcm_encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* key,
                     size_t key_len, const unsigned char* nonce, size_t nonce_len,
                     const unsigned char* aad, size_t aad_len, unsigned char* ciphertext_out,
                     unsigned char* tag_out, size_t tag_len) {
    if (!key || !nonce || !ciphertext_out || !tag_out)
        return false;
    if (plaintext_len > 0 && !plaintext)
        return false;

    auto* ctx = acquire_cipher_ctx();
    if (!ctx)
        return false;

    bool ok = false;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_len),
                                nullptr) != 1)
            break;

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1)
            break;

        if (aad && aad_len > 0) {
            int tmp_len = 0;
            if (EVP_EncryptUpdate(ctx, nullptr, &tmp_len, aad, static_cast<int>(aad_len)) != 1)
                break;
        }

        int out_len = 0;
        if (EVP_EncryptUpdate(ctx, ciphertext_out, &out_len, plaintext,
                              static_cast<int>(plaintext_len)) != 1)
            break;

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext_out + out_len, &final_len) != 1)
            break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_len), tag_out) != 1)
            break;

        ok = true;
    } while (false);

    return ok;
}

bool aes_gcm_decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                     const unsigned char* key, size_t key_len, const unsigned char* nonce,
                     size_t nonce_len, const unsigned char* aad, size_t aad_len,
                     const unsigned char* tag, size_t tag_len, unsigned char* plaintext_out) {
    if (!ciphertext || !key || !nonce || !tag || !plaintext_out)
        return false;

    auto* ctx = acquire_cipher_ctx();
    if (!ctx)
        return false;

    bool ok = false;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            break;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_len),
                                nullptr) != 1)
            break;

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1)
            break;

        if (aad && aad_len > 0) {
            int tmp_len = 0;
            if (EVP_DecryptUpdate(ctx, nullptr, &tmp_len, aad, static_cast<int>(aad_len)) != 1)
                break;
        }

        int out_len = 0;
        if (EVP_DecryptUpdate(ctx, plaintext_out, &out_len, ciphertext,
                              static_cast<int>(ciphertext_len)) != 1)
            break;

        unsigned char tag_copy[64];
        if (tag_len > sizeof(tag_copy))
            break;
        std::memcpy(tag_copy, tag, tag_len);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_len),
                                tag_copy) != 1)
            break;

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext_out + out_len, &final_len) != 1)
            break;

        ok = true;
    } while (false);

    return ok;
}

}  // namespace ssm::v1

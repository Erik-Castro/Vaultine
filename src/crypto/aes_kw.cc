#include "crypto/aes_kw.h"

#include <openssl/evp.h>
#include <cstring>

namespace ssm::v1 {

static const size_t AES_KW_BLOCK = 8;
static const size_t AES_256_KEY_LEN = 32;

bool aes_kw_wrap(
    const unsigned char* plaintext, size_t plaintext_len,
    const unsigned char* kek, size_t kek_len,
    unsigned char* ciphertext_out, size_t* ciphertext_len)
{
    if (!plaintext || !kek || !ciphertext_out || !ciphertext_len)
        return false;

    if (kek_len != AES_256_KEY_LEN)
        return false;

    if (plaintext_len % AES_KW_BLOCK != 0 || plaintext_len == 0)
        return false;

    auto* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool ok = false;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), nullptr,
                               kek, nullptr) != 1)
            break;

        int out_len = 0;
        if (EVP_EncryptUpdate(ctx, ciphertext_out, &out_len,
                              plaintext, static_cast<int>(plaintext_len)) != 1)
            break;

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext_out + out_len,
                                &final_len) != 1)
            break;

        *ciphertext_len = static_cast<size_t>(out_len) + static_cast<size_t>(final_len);
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aes_kw_unwrap(
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* kek, size_t kek_len,
    unsigned char* plaintext_out, size_t* plaintext_len)
{
    if (!ciphertext || !kek || !plaintext_out || !plaintext_len)
        return false;

    if (kek_len != AES_256_KEY_LEN)
        return false;

    if (ciphertext_len % AES_KW_BLOCK != 0)
        return false;

    auto* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    bool ok = false;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap(), nullptr,
                               kek, nullptr) != 1)
            break;

        int out_len = 0;
        if (EVP_DecryptUpdate(ctx, plaintext_out, &out_len,
                              ciphertext, static_cast<int>(ciphertext_len)) != 1)
            break;

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext_out + out_len,
                                &final_len) != 1)
            break;

        *plaintext_len = static_cast<size_t>(out_len) + static_cast<size_t>(final_len);
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

} // namespace ssm::v1

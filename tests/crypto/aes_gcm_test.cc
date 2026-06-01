#include "crypto/aes_gcm.h"

#include <gtest/gtest.h>

#include <cstring>

#include "crypto/random.h"

namespace ssm::v1 {
namespace {

TEST(AesGcmTest, EncryptDecryptRoundTrip) {
    unsigned char key[AES_GCM_KEY_LEN];
    unsigned char nonce[AES_GCM_NONCE_LEN];
    random_bytes(key, sizeof(key));
    random_bytes(nonce, sizeof(nonce));

    const char* plaintext = "hello ssm secret";
    size_t pt_len = std::strlen(plaintext);

    unsigned char ciphertext[64];
    unsigned char tag[AES_GCM_TAG_LEN];

    ASSERT_TRUE(aes_gcm_encrypt(reinterpret_cast<const unsigned char*>(plaintext), pt_len, key,
                                sizeof(key), nonce, sizeof(nonce), nullptr, 0, ciphertext, tag,
                                sizeof(tag)));

    unsigned char decrypted[64];
    ASSERT_TRUE(aes_gcm_decrypt(ciphertext, pt_len, key, sizeof(key), nonce, sizeof(nonce), nullptr,
                                0, tag, sizeof(tag), decrypted));

    EXPECT_EQ(std::memcmp(plaintext, decrypted, pt_len), 0);
}

TEST(AesGcmTest, CorruptedTagFailsDecrypt) {
    unsigned char key[AES_GCM_KEY_LEN];
    unsigned char nonce[AES_GCM_NONCE_LEN];
    random_bytes(key, sizeof(key));
    random_bytes(nonce, sizeof(nonce));

    const char* plaintext = "data with integrity protection";
    size_t pt_len = std::strlen(plaintext);

    unsigned char ciphertext[64];
    unsigned char tag[AES_GCM_TAG_LEN];

    ASSERT_TRUE(aes_gcm_encrypt(reinterpret_cast<const unsigned char*>(plaintext), pt_len, key,
                                sizeof(key), nonce, sizeof(nonce), nullptr, 0, ciphertext, tag,
                                sizeof(tag)));

    tag[0] ^= 0xFF;  // corrupt tag

    unsigned char decrypted[64];
    EXPECT_FALSE(aes_gcm_decrypt(ciphertext, pt_len, key, sizeof(key), nonce, sizeof(nonce),
                                 nullptr, 0, tag, sizeof(tag), decrypted));
}

TEST(AesGcmTest, WrongKeyFailsDecrypt) {
    unsigned char key_a[AES_GCM_KEY_LEN];
    unsigned char key_b[AES_GCM_KEY_LEN];
    unsigned char nonce[AES_GCM_NONCE_LEN];
    random_bytes(key_a, sizeof(key_a));
    random_bytes(key_b, sizeof(key_b));
    random_bytes(nonce, sizeof(nonce));

    const char* plaintext = "secret data";
    size_t pt_len = std::strlen(plaintext);

    unsigned char ciphertext[64];
    unsigned char tag[AES_GCM_TAG_LEN];

    ASSERT_TRUE(aes_gcm_encrypt(reinterpret_cast<const unsigned char*>(plaintext), pt_len, key_a,
                                sizeof(key_a), nonce, sizeof(nonce), nullptr, 0, ciphertext, tag,
                                sizeof(tag)));

    unsigned char decrypted[64];
    EXPECT_FALSE(aes_gcm_decrypt(ciphertext, pt_len, key_b, sizeof(key_b), nonce, sizeof(nonce),
                                 nullptr, 0, tag, sizeof(tag), decrypted));
}

TEST(AesGcmTest, DifferentNonceProducesDifferentCiphertext) {
    unsigned char key[AES_GCM_KEY_LEN];
    unsigned char nonce_a[AES_GCM_NONCE_LEN];
    unsigned char nonce_b[AES_GCM_NONCE_LEN];
    random_bytes(key, sizeof(key));
    random_bytes(nonce_a, sizeof(nonce_a));
    random_bytes(nonce_b, sizeof(nonce_b));

    const char* plaintext = "same data";
    size_t pt_len = std::strlen(plaintext);

    unsigned char ct_a[64], ct_b[64];
    unsigned char tag_a[AES_GCM_TAG_LEN], tag_b[AES_GCM_TAG_LEN];

    ASSERT_TRUE(aes_gcm_encrypt(reinterpret_cast<const unsigned char*>(plaintext), pt_len, key,
                                sizeof(key), nonce_a, sizeof(nonce_a), nullptr, 0, ct_a, tag_a,
                                sizeof(tag_a)));

    ASSERT_TRUE(aes_gcm_encrypt(reinterpret_cast<const unsigned char*>(plaintext), pt_len, key,
                                sizeof(key), nonce_b, sizeof(nonce_b), nullptr, 0, ct_b, tag_b,
                                sizeof(tag_b)));

    EXPECT_NE(std::memcmp(ct_a, ct_b, pt_len), 0);
}

TEST(AesGcmTest, AuthenticatedDataProtectsIntegrity) {
    unsigned char key[AES_GCM_KEY_LEN];
    unsigned char nonce[AES_GCM_NONCE_LEN];
    random_bytes(key, sizeof(key));
    random_bytes(nonce, sizeof(nonce));

    const char* plaintext = "data";
    const char* aad = "authenticated context";
    size_t pt_len = std::strlen(plaintext);

    unsigned char ciphertext[64];
    unsigned char tag[AES_GCM_TAG_LEN];

    ASSERT_TRUE(aes_gcm_encrypt(reinterpret_cast<const unsigned char*>(plaintext), pt_len, key,
                                sizeof(key), nonce, sizeof(nonce),
                                reinterpret_cast<const unsigned char*>(aad), std::strlen(aad),
                                ciphertext, tag, sizeof(tag)));

    unsigned char decrypted[64];
    EXPECT_TRUE(aes_gcm_decrypt(ciphertext, pt_len, key, sizeof(key), nonce, sizeof(nonce),
                                reinterpret_cast<const unsigned char*>(aad), std::strlen(aad), tag,
                                sizeof(tag), decrypted));

    EXPECT_EQ(std::memcmp(plaintext, decrypted, pt_len), 0);

    // Wrong AAD fails
    EXPECT_FALSE(aes_gcm_decrypt(ciphertext, pt_len, key, sizeof(key), nonce, sizeof(nonce),
                                 reinterpret_cast<const unsigned char*>("wrong aad"), 9, tag,
                                 sizeof(tag), decrypted));
}

TEST(AesGcmTest, EmptyPlaintext) {
    unsigned char key[AES_GCM_KEY_LEN];
    unsigned char nonce[AES_GCM_NONCE_LEN];
    random_bytes(key, sizeof(key));
    random_bytes(nonce, sizeof(nonce));

    unsigned char ciphertext[1];
    unsigned char tag[AES_GCM_TAG_LEN];

    EXPECT_TRUE(aes_gcm_encrypt(nullptr, 0, key, sizeof(key), nonce, sizeof(nonce), nullptr, 0,
                                ciphertext, tag, sizeof(tag)));
}

}  // namespace
}  // namespace ssm::v1

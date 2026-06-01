#include "crypto/argon2id.h"

#include <gtest/gtest.h>

#include <cstring>

#include "crypto/random.h"

namespace ssm::v1 {
namespace {

static constexpr size_t SALT_LEN = 16;
static constexpr size_t HASH_LEN = 128;  // crypto_pwhash_STRBYTES

TEST(Argon2idTest, HashAndVerifyRoundTrip) {
    const char* password = "correct horse battery staple";
    unsigned char salt[SALT_LEN];
    random_bytes(salt, sizeof(salt));

    unsigned char hash[HASH_LEN];
    ASSERT_TRUE(argon2id_hash(reinterpret_cast<const unsigned char*>(password),
                              std::strlen(password), salt, sizeof(salt), hash, sizeof(hash)));

    EXPECT_TRUE(argon2id_verify(reinterpret_cast<const unsigned char*>(password),
                                std::strlen(password), hash, sizeof(hash)));
}

TEST(Argon2idTest, WrongPasswordFails) {
    const char* password = "correct horse battery staple";
    const char* wrong = "wrong password";
    unsigned char salt[SALT_LEN];
    random_bytes(salt, sizeof(salt));

    unsigned char hash[HASH_LEN];
    ASSERT_TRUE(argon2id_hash(reinterpret_cast<const unsigned char*>(password),
                              std::strlen(password), salt, sizeof(salt), hash, sizeof(hash)));

    EXPECT_FALSE(argon2id_verify(reinterpret_cast<const unsigned char*>(wrong), std::strlen(wrong),
                                 hash, sizeof(hash)));
}

TEST(Argon2idTest, SamePasswordDifferentSaltsProduceDifferentHashes) {
    const char* password = "my password";

    unsigned char salt_a[SALT_LEN];
    unsigned char salt_b[SALT_LEN];
    random_bytes(salt_a, sizeof(salt_a));
    random_bytes(salt_b, sizeof(salt_b));

    unsigned char hash_a[HASH_LEN];
    unsigned char hash_b[HASH_LEN];

    ASSERT_TRUE(argon2id_hash(reinterpret_cast<const unsigned char*>(password),
                              std::strlen(password), salt_a, sizeof(salt_a), hash_a,
                              sizeof(hash_a)));

    ASSERT_TRUE(argon2id_hash(reinterpret_cast<const unsigned char*>(password),
                              std::strlen(password), salt_b, sizeof(salt_b), hash_b,
                              sizeof(hash_b)));

    EXPECT_NE(std::memcmp(hash_a, hash_b, sizeof(hash_a)), 0);
}

TEST(Argon2idTest, RejectsSmallOutputBuffer) {
    const char* password = "test";
    unsigned char salt[SALT_LEN];
    unsigned char hash[32];
    EXPECT_FALSE(argon2id_hash(reinterpret_cast<const unsigned char*>(password),
                               std::strlen(password), salt, sizeof(salt), hash, sizeof(hash)));
}

TEST(Argon2idTest, VerifyRejectsShortHash) {
    const char* password = "test";
    EXPECT_FALSE(argon2id_verify(reinterpret_cast<const unsigned char*>(password),
                                 std::strlen(password),
                                 reinterpret_cast<const unsigned char*>("too short"), 9));
}

}  // namespace
}  // namespace ssm::v1

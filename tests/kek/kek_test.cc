#include <gtest/gtest.h>

#include "kek/kek.h"
#include "db/database.h"
#include "db/users.h"
#include "db/kek_metadata.h"
#include "db/secrets.h"
#include "crypto/random.h"
#include "crypto/aes_gcm.h"
#include "utils/secure_memory.h"

#include <cstring>
#include <vector>

namespace ssm::v1 {
namespace {

// --- derive wrapping key ---

TEST(KekDeriveTest, ProducesDeterministicKey)
{
    unsigned char auth_hash[64] = {};
    unsigned char salt[KEK_SALT_LEN] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    random_bytes(salt, sizeof(salt));

    unsigned char k1[KEK_KEY_LEN], k2[KEK_KEY_LEN];
    ASSERT_TRUE(kek_derive_wrapping_key(auth_hash, sizeof(auth_hash),
                                        salt, sizeof(salt), k1, sizeof(k1)));
    ASSERT_TRUE(kek_derive_wrapping_key(auth_hash, sizeof(auth_hash),
                                        salt, sizeof(salt), k2, sizeof(k2)));
    EXPECT_EQ(memcmp(k1, k2, sizeof(k1)), 0);
}

TEST(KekDeriveTest, DifferentSaltProducesDifferentKey)
{
    unsigned char auth_hash[64] = {};
    unsigned char salt1[KEK_SALT_LEN] = {};
    unsigned char salt2[KEK_SALT_LEN] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    random_bytes(salt1, sizeof(salt1));
    random_bytes(salt2, sizeof(salt2));

    unsigned char k1[KEK_KEY_LEN], k2[KEK_KEY_LEN];
    ASSERT_TRUE(kek_derive_wrapping_key(auth_hash, sizeof(auth_hash),
                                        salt1, sizeof(salt1), k1, sizeof(k1)));
    ASSERT_TRUE(kek_derive_wrapping_key(auth_hash, sizeof(auth_hash),
                                        salt2, sizeof(salt2), k2, sizeof(k2)));
    EXPECT_NE(memcmp(k1, k2, sizeof(k1)), 0);
}

TEST(KekDeriveTest, RejectsNullInputs)
{
    unsigned char buf[KEK_KEY_LEN];
    unsigned char salt[KEK_SALT_LEN];
    unsigned char hash[64];
    EXPECT_FALSE(kek_derive_wrapping_key(nullptr, 0, salt, sizeof(salt), buf, sizeof(buf)));
    EXPECT_FALSE(kek_derive_wrapping_key(hash, sizeof(hash), nullptr, 0, buf, sizeof(buf)));
    EXPECT_FALSE(kek_derive_wrapping_key(hash, sizeof(hash), salt, sizeof(salt), nullptr, 0));
}

TEST(KekDeriveTest, RejectsShortSalt)
{
    unsigned char hash[64];
    unsigned char buf[KEK_KEY_LEN];
    unsigned char salt[1] = {};
    EXPECT_FALSE(kek_derive_wrapping_key(hash, sizeof(hash), salt, 0, buf, sizeof(buf)));
}

TEST(KekDeriveTest, RejectsWrongOutputSize)
{
    unsigned char hash[64];
    unsigned char salt[KEK_SALT_LEN];
    unsigned char buf[16];
    EXPECT_FALSE(kek_derive_wrapping_key(hash, sizeof(hash), salt, sizeof(salt), buf, sizeof(buf)));
}

// --- generate + unwrap round trip ---

TEST(KekGenerateTest, GenerateAndUnwrapRoundTrip)
{
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];

    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             wrapped, &wrapped_len,
                             salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    EXPECT_EQ(wrapped_len, 40);
    EXPECT_EQ(salt_len, KEK_SALT_LEN);
    EXPECT_GT(strlen(expires_at), 0u);

    unsigned char unwrapped[KEK_KEY_LEN];
    size_t unwrapped_len = sizeof(unwrapped);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len,
                           auth_hash, sizeof(auth_hash),
                           salt, salt_len,
                           unwrapped, &unwrapped_len));
    EXPECT_EQ(unwrapped_len, KEK_KEY_LEN);

    // deterministic: round trip produces same KEK
    unsigned char unwrapped2[KEK_KEY_LEN];
    size_t unwrapped2_len = sizeof(unwrapped2);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len,
                           auth_hash, sizeof(auth_hash),
                           salt, salt_len,
                           unwrapped2, &unwrapped2_len));
    EXPECT_EQ(memcmp(unwrapped, unwrapped2, KEK_KEY_LEN), 0);
}

TEST(KekGenerateTest, SameAuthHashDifferentSalts)
{
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    unsigned char w1[64], w2[64];
    size_t w1_len = sizeof(w1), w2_len = sizeof(w2);
    unsigned char s1[KEK_SALT_LEN], s2[KEK_SALT_LEN];
    size_t s1_len = sizeof(s1), s2_len = sizeof(s2);
    char e1[24], e2[24];

    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             w1, &w1_len, s1, &s1_len, e1, sizeof(e1)));
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             w2, &w2_len, s2, &s2_len, e2, sizeof(e2)));

    EXPECT_NE(memcmp(w1, w2, w1_len), 0);
    EXPECT_NE(memcmp(s1, s2, s1_len), 0);
}

TEST(KekGenerateTest, WrongAuthHashFailsUnwrap)
{
    unsigned char auth_hash[64] = {};
    unsigned char wrong_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    random_bytes(wrong_hash, sizeof(wrong_hash));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];

    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             wrapped, &wrapped_len,
                             salt, &salt_len,
                             expires_at, sizeof(expires_at)));

    unsigned char unwrapped[KEK_KEY_LEN];
    size_t unwrapped_len = sizeof(unwrapped);
    EXPECT_FALSE(kek_unwrap(wrapped, wrapped_len,
                            wrong_hash, sizeof(wrong_hash),
                            salt, salt_len,
                            unwrapped, &unwrapped_len));
}

// --- expiry ---

TEST(KekExpiryTest, FutureDateNotExpired)
{
    char buf[24];
    ASSERT_TRUE(kek_expires_at(1, buf, sizeof(buf)));
    EXPECT_FALSE(kek_is_expired(buf));
}

TEST(KekExpiryTest, PastDateIsExpired)
{
    EXPECT_TRUE(kek_is_expired("2020-01-01T00:00:00Z"));
}

TEST(KekExpiryTest, NullIsExpired)
{
    EXPECT_TRUE(kek_is_expired(nullptr));
}

TEST(KekExpiryTest, InvalidFormatIsExpired)
{
    EXPECT_TRUE(kek_is_expired("not-a-date"));
}

TEST(KekExpiryTest, ExpiresAtNowPlusDays)
{
    char buf[24];
    ASSERT_TRUE(kek_expires_at(90, buf, sizeof(buf)));
    EXPECT_GT(strlen(buf), 0u);
    EXPECT_EQ(buf[4], '-');
    EXPECT_EQ(buf[7], '-');
    EXPECT_EQ(buf[10], 'T');
    EXPECT_EQ(buf[19], 'Z');
    EXPECT_EQ(strlen(buf), 20);
}

TEST(KekExpiryTest, ExpiresAtNegativeDays)
{
    char buf[24];
    ASSERT_TRUE(kek_expires_at(-1, buf, sizeof(buf)));
    EXPECT_TRUE(kek_is_expired(buf));
}

// --- rotation ---

class KekRotationTest : public ::testing::Test
{
protected:
    sqlite3* db_ = nullptr;

    void SetUp() override
    {
        ASSERT_TRUE(db_open(":memory:", nullptr, 0, &db_));
        ASSERT_TRUE(db_create_schema(db_));
    }

    void TearDown() override
    {
        db_close(db_);
    }
};

TEST_F(KekRotationTest, RotateGeneratesNewKek)
{
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "alice", auth_hash, sizeof(auth_hash), &user_id));

    // initial KEK
    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             wrapped, &wrapped_len,
                             salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    // store a secret encrypted with this KEK
    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len,
                           auth_hash, sizeof(auth_hash),
                           salt, salt_len,
                           kek_raw, &kek_len));

    const unsigned char secret_plain[] = "my-secret-key-32bytes...............";
    unsigned char nonce[AES_GCM_NONCE_LEN];
    unsigned char tag[AES_GCM_TAG_LEN];
    unsigned char ciphertext[sizeof(secret_plain)];
    random_bytes(nonce, sizeof(nonce));
    ASSERT_TRUE(aes_gcm_encrypt(secret_plain, sizeof(secret_plain),
                                kek_raw, sizeof(kek_raw),
                                nonce, sizeof(nonce),
                                nullptr, 0,
                                ciphertext, tag, sizeof(tag)));

    ASSERT_TRUE(secrets_store(db_, user_id, "key1",
                              ciphertext, sizeof(ciphertext),
                              nullptr, 0,
                              nonce, sizeof(nonce),
                              tag, sizeof(tag),
                              "test key"));

    // rotate
    ASSERT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    // verify kek_metadata was updated
    kek_row new_row;
    ASSERT_TRUE(kek_find_by_user(db_, user_id, &new_row));
    EXPECT_NE(memcmp(new_row.wrapped_kek.data(), wrapped, wrapped_len), 0);
    EXPECT_NE(memcmp(new_row.salt.data(), salt, salt_len), 0);
    EXPECT_GT(new_row.expires_at.size(), 0u);

    // verify secret can be decrypted with new KEK
    unsigned char new_kek[KEK_KEY_LEN];
    size_t new_kek_len = sizeof(new_kek);
    ASSERT_TRUE(kek_unwrap(new_row.wrapped_kek.data(), new_row.wrapped_kek.size(),
                           auth_hash, sizeof(auth_hash),
                           new_row.salt.data(), new_row.salt.size(),
                           new_kek, &new_kek_len));

    secret_row updated;
    ASSERT_TRUE(secrets_find(db_, user_id, "key1", &updated));

    secure_vector<unsigned char> decrypted(updated.private_key.size());
    ASSERT_TRUE(aes_gcm_decrypt(updated.private_key.data(), updated.private_key.size(),
                                new_kek, sizeof(new_kek),
                                updated.nonce.data(), updated.nonce.size(),
                                nullptr, 0,
                                updated.tag.data(), updated.tag.size(),
                                decrypted.data()));
    EXPECT_EQ(memcmp(decrypted.data(), secret_plain, sizeof(secret_plain)), 0);
}

TEST_F(KekRotationTest, RotateMultipleSecrets)
{
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "bob", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             wrapped, &wrapped_len,
                             salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len,
                           auth_hash, sizeof(auth_hash),
                           salt, salt_len,
                           kek_raw, &kek_len));

    for (int i = 0; i < 3; ++i)
    {
        unsigned char pt[16];
        unsigned char n[AES_GCM_NONCE_LEN];
        unsigned char t[AES_GCM_TAG_LEN];
        unsigned char ct[sizeof(pt)];
        random_bytes(pt, sizeof(pt));
        random_bytes(n, sizeof(n));
        ASSERT_TRUE(aes_gcm_encrypt(pt, sizeof(pt), kek_raw, sizeof(kek_raw),
                                    n, sizeof(n), nullptr, 0, ct, t, sizeof(t)));
        char name[8];
        snprintf(name, sizeof(name), "k%d", i);
        ASSERT_TRUE(secrets_store(db_, user_id, name,
                                  ct, sizeof(ct), nullptr, 0,
                                  n, sizeof(n), t, sizeof(t), nullptr));
    }

    ASSERT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    // verify all 3 secrets still accessible with new KEK
    kek_row new_row;
    ASSERT_TRUE(kek_find_by_user(db_, user_id, &new_row));
    unsigned char new_kek[KEK_KEY_LEN];
    size_t new_kek_len = sizeof(new_kek);
    ASSERT_TRUE(kek_unwrap(new_row.wrapped_kek.data(), new_row.wrapped_kek.size(),
                           auth_hash, sizeof(auth_hash),
                           new_row.salt.data(), new_row.salt.size(),
                           new_kek, &new_kek_len));

    for (int i = 0; i < 3; ++i)
    {
        char name[8];
        snprintf(name, sizeof(name), "k%d", i);
        secret_row sr;
        ASSERT_TRUE(secrets_find(db_, user_id, name, &sr));
        secure_vector<unsigned char> dec(sr.private_key.size());
        ASSERT_TRUE(aes_gcm_decrypt(sr.private_key.data(), sr.private_key.size(),
                                    new_kek, sizeof(new_kek),
                                    sr.nonce.data(), sr.nonce.size(),
                                    nullptr, 0,
                                    sr.tag.data(), sr.tag.size(),
                                    dec.data()));
    }
}

TEST_F(KekRotationTest, RotateWithoutSecretsSucceeds)
{
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "carol", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             wrapped, &wrapped_len,
                             salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    EXPECT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    kek_row new_row;
    ASSERT_TRUE(kek_find_by_user(db_, user_id, &new_row));
    EXPECT_NE(memcmp(new_row.wrapped_kek.data(), wrapped, wrapped_len), 0);
}

TEST_F(KekRotationTest, WrongAuthHashFailsRotation)
{
    unsigned char auth_hash[64] = {};
    unsigned char wrong_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    random_bytes(wrong_hash, sizeof(wrong_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "dave", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             wrapped, &wrapped_len,
                             salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    EXPECT_FALSE(kek_rotate(db_, user_id, wrong_hash, sizeof(wrong_hash)));
}

TEST_F(KekRotationTest, RotateWithPublicKey)
{
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "eve", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             wrapped, &wrapped_len,
                             salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len,
                           auth_hash, sizeof(auth_hash),
                           salt, salt_len,
                           kek_raw, &kek_len));

    unsigned char priv[] = "private-key-material-here-32bytes!";
    unsigned char pub[] = "public-key-material-here!";
    unsigned char nonce[AES_GCM_NONCE_LEN];
    unsigned char priv_tag[AES_GCM_TAG_LEN];
    unsigned char priv_ct[sizeof(priv)];
    random_bytes(nonce, sizeof(nonce));

    ASSERT_TRUE(aes_gcm_encrypt(priv, sizeof(priv), kek_raw, sizeof(kek_raw),
                                nonce, sizeof(nonce), nullptr, 0,
                                priv_ct, priv_tag, sizeof(priv_tag)));

    // public_key is stored plaintext (public keys are public)
    ASSERT_TRUE(secrets_store(db_, user_id, "keypair",
                              priv_ct, sizeof(priv_ct),
                              pub, sizeof(pub),
                              nonce, sizeof(nonce),
                              priv_tag, sizeof(priv_tag),
                              "keypair with pub"));

    ASSERT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    kek_row new_row;
    ASSERT_TRUE(kek_find_by_user(db_, user_id, &new_row));
    unsigned char new_kek[KEK_KEY_LEN];
    size_t new_kek_len = sizeof(new_kek);
    ASSERT_TRUE(kek_unwrap(new_row.wrapped_kek.data(), new_row.wrapped_kek.size(),
                           auth_hash, sizeof(auth_hash),
                           new_row.salt.data(), new_row.salt.size(),
                           new_kek, &new_kek_len));

    secret_row sr;
    ASSERT_TRUE(secrets_find(db_, user_id, "keypair", &sr));
    ASSERT_FALSE(sr.public_key.empty());

    secure_vector<unsigned char> dec_priv(sr.private_key.size());
    ASSERT_TRUE(aes_gcm_decrypt(sr.private_key.data(), sr.private_key.size(),
                                new_kek, sizeof(new_kek),
                                sr.nonce.data(), sr.nonce.size(),
                                nullptr, 0,
                                sr.tag.data(), sr.tag.size(),
                                dec_priv.data()));
    EXPECT_EQ(memcmp(dec_priv.data(), priv, sizeof(priv)), 0);

    // public_key is preserved plaintext
    ASSERT_EQ(sr.public_key.size(), sizeof(pub));
    EXPECT_EQ(memcmp(sr.public_key.data(), pub, sizeof(pub)), 0);
}

TEST_F(KekRotationTest, NoKekMetadataFailsRotation)
{
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "frank", auth_hash, sizeof(auth_hash), &user_id));

    EXPECT_FALSE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));
}

TEST_F(KekRotationTest, RotationPreservesAllSecretsCount)
{
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "grace", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash),
                             wrapped, &wrapped_len,
                             salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len,
                           auth_hash, sizeof(auth_hash),
                           salt, salt_len,
                           kek_raw, &kek_len));

    for (int i = 0; i < 5; ++i)
    {
        unsigned char pt[8];
        unsigned char n[AES_GCM_NONCE_LEN];
        unsigned char t[AES_GCM_TAG_LEN];
        unsigned char ct[sizeof(pt)];
        random_bytes(pt, sizeof(pt));
        random_bytes(n, sizeof(n));
        ASSERT_TRUE(aes_gcm_encrypt(pt, sizeof(pt), kek_raw, sizeof(kek_raw),
                                    n, sizeof(n), nullptr, 0, ct, t, sizeof(t)));
        char name[8];
        snprintf(name, sizeof(name), "s%d", i);
        ASSERT_TRUE(secrets_store(db_, user_id, name,
                                  ct, sizeof(ct), nullptr, 0,
                                  n, sizeof(n), t, sizeof(t), nullptr));
    }

    std::vector<secret_row> before;
    ASSERT_TRUE(secrets_list_for_user(db_, user_id, &before));
    EXPECT_EQ(before.size(), 5u);

    ASSERT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    std::vector<secret_row> after;
    ASSERT_TRUE(secrets_list_for_user(db_, user_id, &after));
    EXPECT_EQ(after.size(), 5u);
}

} // namespace
} // namespace ssm::v1

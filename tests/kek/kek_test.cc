#include "kek/kek.h"

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "crypto/aes_gcm.h"
#include "crypto/aes_kw.h"
#include "crypto/random.h"
#include "db/database.h"
#include "db/kek_archive.h"
#include "db/kek_metadata.h"
#include "db/secrets.h"
#include "db/users.h"
#include "utils/secure_memory.h"

namespace ssm::v1 {
namespace {

// --- derive wrapping key ---

TEST(KekDeriveTest, ProducesDeterministicKey) {
    unsigned char auth_hash[64] = {};
    unsigned char salt[KEK_SALT_LEN] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    random_bytes(salt, sizeof(salt));

    unsigned char k1[KEK_KEY_LEN], k2[KEK_KEY_LEN];
    ASSERT_TRUE(
        kek_derive_wrapping_key(auth_hash, sizeof(auth_hash), salt, sizeof(salt), k1, sizeof(k1)));
    ASSERT_TRUE(
        kek_derive_wrapping_key(auth_hash, sizeof(auth_hash), salt, sizeof(salt), k2, sizeof(k2)));
    EXPECT_EQ(memcmp(k1, k2, sizeof(k1)), 0);
}

TEST(KekDeriveTest, DifferentSaltProducesDifferentKey) {
    unsigned char auth_hash[64] = {};
    unsigned char salt1[KEK_SALT_LEN] = {};
    unsigned char salt2[KEK_SALT_LEN] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    random_bytes(salt1, sizeof(salt1));
    random_bytes(salt2, sizeof(salt2));

    unsigned char k1[KEK_KEY_LEN], k2[KEK_KEY_LEN];
    ASSERT_TRUE(kek_derive_wrapping_key(auth_hash, sizeof(auth_hash), salt1, sizeof(salt1), k1,
                                        sizeof(k1)));
    ASSERT_TRUE(kek_derive_wrapping_key(auth_hash, sizeof(auth_hash), salt2, sizeof(salt2), k2,
                                        sizeof(k2)));
    EXPECT_NE(memcmp(k1, k2, sizeof(k1)), 0);
}

TEST(KekDeriveTest, RejectsNullInputs) {
    unsigned char buf[KEK_KEY_LEN];
    unsigned char salt[KEK_SALT_LEN];
    unsigned char hash[64];
    EXPECT_FALSE(kek_derive_wrapping_key(nullptr, 0, salt, sizeof(salt), buf, sizeof(buf)));
    EXPECT_FALSE(kek_derive_wrapping_key(hash, sizeof(hash), nullptr, 0, buf, sizeof(buf)));
    EXPECT_FALSE(kek_derive_wrapping_key(hash, sizeof(hash), salt, sizeof(salt), nullptr, 0));
}

TEST(KekDeriveTest, RejectsShortSalt) {
    unsigned char hash[64];
    unsigned char buf[KEK_KEY_LEN];
    unsigned char salt[1] = {};
    EXPECT_FALSE(kek_derive_wrapping_key(hash, sizeof(hash), salt, 0, buf, sizeof(buf)));
}

TEST(KekDeriveTest, RejectsWrongOutputSize) {
    unsigned char hash[64];
    unsigned char salt[KEK_SALT_LEN];
    unsigned char buf[16];
    EXPECT_FALSE(kek_derive_wrapping_key(hash, sizeof(hash), salt, sizeof(salt), buf, sizeof(buf)));
}

// --- generate + unwrap round trip ---

TEST(KekGenerateTest, GenerateAndUnwrapRoundTrip) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];

    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash), wrapped, &wrapped_len, salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    EXPECT_EQ(wrapped_len, 40);
    EXPECT_EQ(salt_len, KEK_SALT_LEN);
    EXPECT_GT(strlen(expires_at), 0u);

    unsigned char unwrapped[KEK_KEY_LEN];
    size_t unwrapped_len = sizeof(unwrapped);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len, auth_hash, sizeof(auth_hash), salt, salt_len,
                           unwrapped, &unwrapped_len));
    EXPECT_EQ(unwrapped_len, KEK_KEY_LEN);

    // deterministic: round trip produces same KEK
    unsigned char unwrapped2[KEK_KEY_LEN];
    size_t unwrapped2_len = sizeof(unwrapped2);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len, auth_hash, sizeof(auth_hash), salt, salt_len,
                           unwrapped2, &unwrapped2_len));
    EXPECT_EQ(memcmp(unwrapped, unwrapped2, KEK_KEY_LEN), 0);
}

TEST(KekGenerateTest, SameAuthHashDifferentSalts) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    unsigned char w1[64], w2[64];
    size_t w1_len = sizeof(w1), w2_len = sizeof(w2);
    unsigned char s1[KEK_SALT_LEN], s2[KEK_SALT_LEN];
    size_t s1_len = sizeof(s1), s2_len = sizeof(s2);
    char e1[24], e2[24];

    ASSERT_TRUE(
        kek_generate(auth_hash, sizeof(auth_hash), w1, &w1_len, s1, &s1_len, e1, sizeof(e1)));
    ASSERT_TRUE(
        kek_generate(auth_hash, sizeof(auth_hash), w2, &w2_len, s2, &s2_len, e2, sizeof(e2)));

    EXPECT_NE(memcmp(w1, w2, w1_len), 0);
    EXPECT_NE(memcmp(s1, s2, s1_len), 0);
}

TEST(KekGenerateTest, WrongAuthHashFailsUnwrap) {
    unsigned char auth_hash[64] = {};
    unsigned char wrong_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    random_bytes(wrong_hash, sizeof(wrong_hash));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];

    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash), wrapped, &wrapped_len, salt, &salt_len,
                             expires_at, sizeof(expires_at)));

    unsigned char unwrapped[KEK_KEY_LEN];
    size_t unwrapped_len = sizeof(unwrapped);
    EXPECT_FALSE(kek_unwrap(wrapped, wrapped_len, wrong_hash, sizeof(wrong_hash), salt, salt_len,
                             unwrapped, &unwrapped_len));
}

// --- expiry ---

TEST(KekExpiryTest, FutureDateNotExpired) {
    char buf[24];
    ASSERT_TRUE(kek_expires_at(1, buf, sizeof(buf)));
    EXPECT_FALSE(kek_is_expired(buf));
}

TEST(KekExpiryTest, PastDateIsExpired) { EXPECT_TRUE(kek_is_expired("2020-01-01T00:00:00Z")); }

TEST(KekExpiryTest, NullIsExpired) { EXPECT_TRUE(kek_is_expired(nullptr)); }

TEST(KekExpiryTest, InvalidFormatIsExpired) { EXPECT_TRUE(kek_is_expired("not-a-date")); }

TEST(KekExpiryTest, ExpiresAtNowPlusDays) {
    char buf[24];
    ASSERT_TRUE(kek_expires_at(90, buf, sizeof(buf)));
    EXPECT_GT(strlen(buf), 0u);
    EXPECT_EQ(buf[4], '-');
    EXPECT_EQ(buf[7], '-');
    EXPECT_EQ(buf[10], 'T');
    EXPECT_EQ(buf[19], 'Z');
    EXPECT_EQ(strlen(buf), 20);
}

TEST(KekExpiryTest, ExpiresAtNegativeDays) {
    char buf[24];
    ASSERT_TRUE(kek_expires_at(-1, buf, sizeof(buf)));
    EXPECT_TRUE(kek_is_expired(buf));
}

// --- rotation (O(1) archive-and-switch) ---

class KekRotationTest : public ::testing::Test {
protected:
    sqlite3* db_ = nullptr;

    void SetUp() override {
        ASSERT_TRUE(db_open(":memory:", nullptr, 0, &db_));
        ASSERT_TRUE(db_create_schema(db_));
    }

    void TearDown() override { db_close(db_); }
};

TEST_F(KekRotationTest, RotateGeneratesNewKekAndArchivesOld) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "alice", auth_hash, sizeof(auth_hash), &user_id));

    // initial KEK (version 1)
    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash), wrapped, &wrapped_len, salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    // store a secret encrypted with version 1 KEK
    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len, auth_hash, sizeof(auth_hash), salt, salt_len,
                           kek_raw, &kek_len));

    const unsigned char secret_plain[] = "my-secret-key-32bytes...............";
    unsigned char nonce[AES_GCM_NONCE_LEN];
    unsigned char tag[AES_GCM_TAG_LEN];
    unsigned char ciphertext[sizeof(secret_plain)];
    random_bytes(nonce, sizeof(nonce));
    ASSERT_TRUE(aes_gcm_encrypt(secret_plain, sizeof(secret_plain), kek_raw, sizeof(kek_raw), nonce,
                                sizeof(nonce), nullptr, 0, ciphertext, tag, sizeof(tag)));
    ASSERT_TRUE(secrets_store(db_, user_id, "key1", ciphertext, sizeof(ciphertext), nullptr, 0,
                              nonce, sizeof(nonce), tag, sizeof(tag), "test key"));

    // capture pre-rotation state
    kek_row before;
    ASSERT_TRUE(kek_find_by_user(db_, user_id, &before));
    EXPECT_EQ(before.kek_version, 1);

    secret_row secret_before;
    ASSERT_TRUE(secrets_find(db_, user_id, "key1", &secret_before));
    auto saved_cipher = secret_before.private_key;

    // rotate (O(1) — archive current, generate new, no secrets loop)
    ASSERT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    // verify kek_metadata was updated (version incremented)
    kek_row after;
    ASSERT_TRUE(kek_find_by_user(db_, user_id, &after));
    EXPECT_EQ(after.kek_version, 2);
    EXPECT_NE(memcmp(after.wrapped_kek.data(), wrapped, wrapped_len), 0);

    // verify archive entry for version 1 exists
    kek_archive_row archived;
    ASSERT_TRUE(kek_archive_find_by_version(db_, user_id, 1, &archived));
    EXPECT_EQ(archived.user_id, user_id);
    EXPECT_EQ(archived.kek_version, 1);
    EXPECT_EQ(archived.wrapped_kek.size(), before.wrapped_kek.size());
    EXPECT_EQ(memcmp(archived.wrapped_kek.data(), before.wrapped_kek.data(),
                     before.wrapped_kek.size()), 0);
    EXPECT_EQ(archived.salt.size(), before.salt.size());
    EXPECT_FALSE(archived.expires_at.empty());
    EXPECT_FALSE(archived.created_at.empty());

    // verify secret was NOT modified (O(1) guarantee)
    secret_row secret_after;
    ASSERT_TRUE(secrets_find(db_, user_id, "key1", &secret_after));
    EXPECT_EQ(secret_after.kek_version, 1);  // still at version 1
    EXPECT_EQ(memcmp(secret_after.private_key.data(), saved_cipher.data(), saved_cipher.size()), 0);
}

TEST_F(KekRotationTest, O1RotationWith1000SecretsNoSecretScan) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "o1bulk", auth_hash, sizeof(auth_hash), &user_id));

    // initial KEK
    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash), wrapped, &wrapped_len, salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    // Insert 1005 fake secrets directly (no crypto needed)
    ASSERT_EQ(sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr), SQLITE_OK);
    const char* insert_sql =
        "INSERT INTO secrets (user_id, name, private_key, nonce, tag, kek_version) "
        "VALUES (?, ?, X'00', X'00', X'00', 1)";
    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(db_, insert_sql, -1, &stmt, nullptr), SQLITE_OK);
    for (int i = 0; i < 1005; ++i) {
        char name[16];
        std::snprintf(name, sizeof(name), "bulk_%d", i);
        sqlite3_reset(stmt);
        sqlite3_bind_int64(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
        ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    }
    sqlite3_finalize(stmt);
    ASSERT_EQ(sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr), SQLITE_OK);

    // Verify 1005 secrets exist
    int64_t count_before = 0;
    ASSERT_TRUE(secrets_count_by_kek_version(db_, user_id, 1, &count_before));
    EXPECT_EQ(count_before, 1005);

    // Rotate — O(1) must NOT scan secrets
    ASSERT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    // Verify NO secrets were updated — all still at kek_version=1
    int64_t count_after = 0;
    ASSERT_TRUE(secrets_count_by_kek_version(db_, user_id, 1, &count_after));
    EXPECT_EQ(count_after, 1005);

    // Verify kek_version incremented
    kek_row meta;
    ASSERT_TRUE(kek_find_by_user(db_, user_id, &meta));
    EXPECT_EQ(meta.kek_version, 2);

    // Verify archive entry was created
    kek_archive_row archived;
    ASSERT_TRUE(kek_archive_find_by_version(db_, user_id, 1, &archived));
    EXPECT_EQ(archived.kek_version, 1);
}

TEST_F(KekRotationTest, O1RotationNullParams) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    EXPECT_FALSE(kek_rotate(nullptr, 1, auth_hash, sizeof(auth_hash)));
    EXPECT_FALSE(kek_rotate(db_, 1, nullptr, 0));
}

TEST_F(KekRotationTest, NoKekMetadataFailsRotation) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "nokek", auth_hash, sizeof(auth_hash), &user_id));

    EXPECT_FALSE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));
}

TEST_F(KekRotationTest, WrongAuthHashFailsRotation) {
    unsigned char auth_hash[64] = {};
    unsigned char wrong_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));
    random_bytes(wrong_hash, sizeof(wrong_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "wrongauth", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash), wrapped, &wrapped_len, salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    EXPECT_FALSE(kek_rotate(db_, user_id, wrong_hash, sizeof(wrong_hash)));
}

TEST_F(KekRotationTest, RotateWithoutSecretsSucceeds) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "noscrts", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash), wrapped, &wrapped_len, salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    EXPECT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    kek_row new_row;
    ASSERT_TRUE(kek_find_by_user(db_, user_id, &new_row));
    EXPECT_EQ(new_row.kek_version, 2);
    EXPECT_NE(memcmp(new_row.wrapped_kek.data(), wrapped, wrapped_len), 0);

    // Verify archive entry for version 1
    kek_archive_row archived;
    ASSERT_TRUE(kek_archive_find_by_version(db_, user_id, 1, &archived));
    EXPECT_EQ(archived.user_id, user_id);
    EXPECT_EQ(archived.kek_version, 1);
}

TEST_F(KekRotationTest, RotationPreservesAllSecretsCount) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "cnttest", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash), wrapped, &wrapped_len, salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len, auth_hash, sizeof(auth_hash), salt, salt_len,
                           kek_raw, &kek_len));

    for (int i = 0; i < 5; ++i) {
        unsigned char pt[8];
        unsigned char n[AES_GCM_NONCE_LEN];
        unsigned char t[AES_GCM_TAG_LEN];
        unsigned char ct[sizeof(pt)];
        random_bytes(pt, sizeof(pt));
        random_bytes(n, sizeof(n));
        ASSERT_TRUE(aes_gcm_encrypt(pt, sizeof(pt), kek_raw, sizeof(kek_raw), n, sizeof(n), nullptr,
                                     0, ct, t, sizeof(t)));
        char name[8];
        std::snprintf(name, sizeof(name), "s%d", i);
        ASSERT_TRUE(secrets_store(db_, user_id, name, ct, sizeof(ct), nullptr, 0, n, sizeof(n), t,
                                  sizeof(t), nullptr));
    }

    std::vector<secret_row> before;
    ASSERT_TRUE(secrets_list_for_user(db_, user_id, &before));
    EXPECT_EQ(before.size(), 5u);

    ASSERT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    std::vector<secret_row> after;
    ASSERT_TRUE(secrets_list_for_user(db_, user_id, &after));
    EXPECT_EQ(after.size(), 5u);
}

TEST_F(KekRotationTest, RotateWithPublicKeyPreserved) {
    unsigned char auth_hash[64] = {};
    random_bytes(auth_hash, sizeof(auth_hash));

    int64_t user_id;
    ASSERT_TRUE(users_create(db_, "pubtest", auth_hash, sizeof(auth_hash), &user_id));

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];
    ASSERT_TRUE(kek_generate(auth_hash, sizeof(auth_hash), wrapped, &wrapped_len, salt, &salt_len,
                             expires_at, sizeof(expires_at)));
    ASSERT_TRUE(kek_store(db_, user_id, wrapped, wrapped_len, salt, salt_len, expires_at));

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    ASSERT_TRUE(kek_unwrap(wrapped, wrapped_len, auth_hash, sizeof(auth_hash), salt, salt_len,
                           kek_raw, &kek_len));

    unsigned char priv[] = "private-key-material-here-32bytes!";
    unsigned char pub[] = "public-key-material-here!";
    unsigned char nonce[AES_GCM_NONCE_LEN];
    unsigned char priv_tag[AES_GCM_TAG_LEN];
    unsigned char priv_ct[sizeof(priv)];
    random_bytes(nonce, sizeof(nonce));
    ASSERT_TRUE(aes_gcm_encrypt(priv, sizeof(priv), kek_raw, sizeof(kek_raw), nonce, sizeof(nonce),
                                nullptr, 0, priv_ct, priv_tag, sizeof(priv_tag)));
    ASSERT_TRUE(secrets_store(db_, user_id, "keypair", priv_ct, sizeof(priv_ct), pub, sizeof(pub),
                              nonce, sizeof(nonce), priv_tag, sizeof(priv_tag), "keypair with pub"));

    ASSERT_TRUE(kek_rotate(db_, user_id, auth_hash, sizeof(auth_hash)));

    // Verify archive entry
    kek_archive_row archived;
    ASSERT_TRUE(kek_archive_find_by_version(db_, user_id, 1, &archived));
    EXPECT_EQ(archived.kek_version, 1);

    // Verify secret public_key is preserved
    secret_row sr;
    ASSERT_TRUE(secrets_find(db_, user_id, "keypair", &sr));
    ASSERT_FALSE(sr.public_key.empty());
    ASSERT_EQ(sr.public_key.size(), sizeof(pub));
    EXPECT_EQ(memcmp(sr.public_key.data(), pub, sizeof(pub)), 0);

    // Verify secret still at kek_version=1 (O(1) guarantee)
    EXPECT_EQ(sr.kek_version, 1);
}

}  // namespace
}  // namespace ssm::v1

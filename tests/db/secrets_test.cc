#include "db/secrets.h"

#include <gtest/gtest.h>
#include <sqlcipher.h>

#include "db/database.h"
#include "db/users.h"

namespace ssm::v1 {
namespace {

static const unsigned char TEST_KEY[] = "test-key-32-bytes-for-sqlcipher!!";
static const unsigned char HASH[] =
    "$argon2id$v=19$m=65536,t=2,p=1$test-salt-here-1234$hash-value-goes-here!";
static const unsigned char PRIV_KEY[] = "private-key-data-32-bytes!!";
static const unsigned char PUB_KEY[] = "public-key-data-32-bytes!!";
static const unsigned char NONCE[] = "12b-nonce!!";
static const unsigned char TAG[] = "16b-tag--here!!!";

class SecretsTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(db_open(":memory:", TEST_KEY, sizeof(TEST_KEY) - 1, &db_));
        ASSERT_TRUE(db_create_schema(db_));

        int64_t uid = 0;
        ASSERT_TRUE(users_create(db_, "alice", HASH, sizeof(HASH), &uid));
        user_id_ = uid;
    }

    void TearDown() override { db_close(db_); }

    sqlite3* db_ = nullptr;
    int64_t user_id_ = 0;
};

TEST_F(SecretsTest, StoreAndFind) {
    EXPECT_TRUE(secrets_store(db_, user_id_, "my-key", PRIV_KEY, sizeof(PRIV_KEY), PUB_KEY,
                              sizeof(PUB_KEY), NONCE, sizeof(NONCE), TAG, sizeof(TAG),
                              "my ssh key"));

    secret_row row{};
    EXPECT_TRUE(secrets_find(db_, user_id_, "my-key", &row));
    EXPECT_EQ(row.private_key.size(), sizeof(PRIV_KEY));
    EXPECT_EQ(row.public_key.size(), sizeof(PUB_KEY));
    EXPECT_EQ(row.nonce.size(), sizeof(NONCE));
    EXPECT_EQ(row.tag.size(), sizeof(TAG));
    EXPECT_EQ(row.name, "my-key");
    EXPECT_EQ(row.description, "my ssh key");
}

TEST_F(SecretsTest, FindNonExistentReturnsFalse) {
    secret_row row{};
    EXPECT_FALSE(secrets_find(db_, user_id_, "nonexistent", &row));
}

TEST_F(SecretsTest, DeleteSecret) {
    ASSERT_TRUE(secrets_store(db_, user_id_, "my-key", PRIV_KEY, sizeof(PRIV_KEY), nullptr, 0,
                              NONCE, sizeof(NONCE), TAG, sizeof(TAG), nullptr));

    EXPECT_TRUE(secrets_delete(db_, user_id_, "my-key"));

    secret_row row{};
    EXPECT_FALSE(secrets_find(db_, user_id_, "my-key", &row));
}

TEST_F(SecretsTest, DeleteNonExistentReturnsFalse) {
    EXPECT_FALSE(secrets_delete(db_, user_id_, "ghost"));
}

TEST_F(SecretsTest, ListSecrets) {
    ASSERT_TRUE(secrets_store(db_, user_id_, "ssh", PRIV_KEY, sizeof(PRIV_KEY), PUB_KEY,
                              sizeof(PUB_KEY), NONCE, sizeof(NONCE), TAG, sizeof(TAG), "ssh key"));

    ASSERT_TRUE(secrets_store(db_, user_id_, "gpg", PRIV_KEY, sizeof(PRIV_KEY), nullptr, 0, NONCE,
                              sizeof(NONCE), TAG, sizeof(TAG), "gpg key"));

    std::vector<secret_row> rows;
    EXPECT_TRUE(secrets_list_for_user(db_, user_id_, &rows));
    EXPECT_EQ(rows.size(), 2);
}

TEST_F(SecretsTest, ListEmptyUserReturnsEmpty) {
    std::vector<secret_row> rows;
    EXPECT_TRUE(secrets_list_for_user(db_, user_id_, &rows));
    EXPECT_TRUE(rows.empty());
}

TEST_F(SecretsTest, DeleteUserCascadesSecrets) {
    ASSERT_TRUE(secrets_store(db_, user_id_, "my-key", PRIV_KEY, sizeof(PRIV_KEY), nullptr, 0,
                              NONCE, sizeof(NONCE), TAG, sizeof(TAG), nullptr));

    EXPECT_TRUE(users_delete(db_, user_id_));

    secret_row row{};
    EXPECT_FALSE(secrets_find(db_, user_id_, "my-key", &row));
}

TEST_F(SecretsTest, MultipleSecretsWithDifferentNames) {
    EXPECT_TRUE(secrets_store(db_, user_id_, "key-a", PRIV_KEY, sizeof(PRIV_KEY), nullptr, 0, NONCE,
                              sizeof(NONCE), TAG, sizeof(TAG), nullptr));

    EXPECT_TRUE(secrets_store(db_, user_id_, "key-b", PRIV_KEY, sizeof(PRIV_KEY), nullptr, 0, NONCE,
                              sizeof(NONCE), TAG, sizeof(TAG), nullptr));

    secret_row row_a;
    EXPECT_TRUE(secrets_find(db_, user_id_, "key-a", &row_a));
    EXPECT_EQ(row_a.name, "key-a");

    secret_row row_b;
    EXPECT_TRUE(secrets_find(db_, user_id_, "key-b", &row_b));
    EXPECT_EQ(row_b.name, "key-b");
}

}  // namespace
}  // namespace ssm::v1

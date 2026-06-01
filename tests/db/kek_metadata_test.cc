#include "db/kek_metadata.h"

#include <gtest/gtest.h>
#include <sqlcipher.h>

#include "db/database.h"
#include "db/users.h"

namespace ssm::v1 {
namespace {

static const unsigned char TEST_KEY[] = "test-key-32-bytes-for-sqlcipher!!";
static const unsigned char HASH[] =
    "$argon2id$v=19$m=65536,t=2,p=1$test-salt-here-1234$hash-value-goes-here!";
static const unsigned char WRAPPED_KEK[] = "fake-wrapped-kek-32-bytes!!!!";
static const unsigned char SALT[] = "salt-bytes-16!!";

class KekTest : public ::testing::Test {
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

TEST_F(KekTest, StoreAndFind) {
    EXPECT_TRUE(kek_store(db_, user_id_, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT, sizeof(SALT),
                          "2099-12-31T23:59:59Z"));

    kek_row row{};
    EXPECT_TRUE(kek_find_by_user(db_, user_id_, &row));
    EXPECT_EQ(row.wrapped_kek.size(), sizeof(WRAPPED_KEK));
    EXPECT_EQ(row.salt.size(), sizeof(SALT));
    EXPECT_EQ(row.expires_at, "2099-12-31T23:59:59Z");
}

TEST_F(KekTest, FindNonExistentReturnsFalse) {
    kek_row row{};
    EXPECT_FALSE(kek_find_by_user(db_, 999, &row));
}

TEST_F(KekTest, DuplicateUserKekFails) {
    EXPECT_TRUE(kek_store(db_, user_id_, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT, sizeof(SALT),
                          "2099-12-31T23:59:59Z"));

    EXPECT_FALSE(kek_store(db_, user_id_, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT, sizeof(SALT),
                           "2099-12-31T23:59:59Z"));
}

TEST_F(KekTest, UpdateKek) {
    ASSERT_TRUE(kek_store(db_, user_id_, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT, sizeof(SALT),
                          "2099-12-31T23:59:59Z"));

    const unsigned char new_kek[] = "new-wrapped-kek-32-bytes!!!!!!!!";
    const unsigned char new_salt[] = "new-salt-16!!";

    EXPECT_TRUE(kek_update(db_, user_id_, new_kek, sizeof(new_kek), new_salt, sizeof(new_salt),
                           "2099-01-01T00:00:00Z", 1));

    kek_row row{};
    ASSERT_TRUE(kek_find_by_user(db_, user_id_, &row));
    EXPECT_EQ(row.wrapped_kek.size(), sizeof(new_kek));
    EXPECT_EQ(row.salt.size(), sizeof(new_salt));
    EXPECT_EQ(row.expires_at, "2099-01-01T00:00:00Z");
    EXPECT_EQ(row.kek_version, 2);  // version incremented
}

TEST_F(KekTest, UpdateKekWithWrongVersionFails) {
    ASSERT_TRUE(kek_store(db_, user_id_, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT, sizeof(SALT),
                          "2099-12-31T23:59:59Z"));

    const unsigned char new_kek[] = "new-wrapped-kek-32-bytes!!!!!!!!";
    const unsigned char new_salt[] = "new-salt-16!!";

    EXPECT_FALSE(kek_update(db_, user_id_, new_kek, sizeof(new_kek), new_salt, sizeof(new_salt),
                            "2099-01-01T00:00:00Z", 99));

    kek_row row{};
    ASSERT_TRUE(kek_find_by_user(db_, user_id_, &row));
    EXPECT_EQ(row.kek_version, 1);  // unchanged
}

TEST_F(KekTest, DeleteKek) {
    ASSERT_TRUE(kek_store(db_, user_id_, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT, sizeof(SALT),
                          "2099-12-31T23:59:59Z"));

    EXPECT_TRUE(kek_delete(db_, user_id_));

    kek_row row{};
    EXPECT_FALSE(kek_find_by_user(db_, user_id_, &row));
}

TEST_F(KekTest, DeleteUserCascadesKek) {
    ASSERT_TRUE(kek_store(db_, user_id_, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT, sizeof(SALT),
                          "2099-12-31T23:59:59Z"));

    EXPECT_TRUE(users_delete(db_, user_id_));

    kek_row row{};
    EXPECT_FALSE(kek_find_by_user(db_, user_id_, &row));
}

}  // namespace
}  // namespace ssm::v1

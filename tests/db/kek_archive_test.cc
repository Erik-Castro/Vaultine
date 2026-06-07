#include "db/kek_archive.h"

#include <gtest/gtest.h>
#include <sqlcipher.h>

#include <cstring>

#include "db/database.h"
#include "db/migrations.h"
#include "db/users.h"

namespace ssm::v1 {
namespace {

static const unsigned char TEST_KEY[] = "test-key-32-bytes-for-sqlcipher!!";
static const unsigned char HASH[] =
    "$argon2id$v=19$m=65536,t=2,p=1$test-salt-here-1234$hash-value-goes-here!";

class KekArchiveTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(db_open(":memory:", TEST_KEY, sizeof(TEST_KEY) - 1, &db_));
        ASSERT_TRUE(db_create_schema(db_));
        ASSERT_TRUE(db_migrate(db_));

        int64_t uid = 0;
        ASSERT_TRUE(users_create(db_, "alice", HASH, sizeof(HASH), &uid));
        user_id_ = uid;

        int64_t uid2 = 0;
        ASSERT_TRUE(users_create(db_, "bob", HASH, sizeof(HASH), &uid2));
        user2_id_ = uid2;
    }

    void TearDown() override { db_close(db_); }

    sqlite3* db_ = nullptr;
    int64_t user_id_ = 0;
    int64_t user2_id_ = 0;
};

static const unsigned char WRAPPED_KEK[] = "fake-wrapped-kek-32-bytes-for-archive!!";
static const unsigned char SALT[] = "salt-bytes-16!!";

TEST_F(KekArchiveTest, StoreAndFindByVersion) {
    EXPECT_TRUE(kek_archive_store(db_, user_id_, 1, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                  sizeof(SALT), "2099-12-31T23:59:59Z"));

    kek_archive_row row{};
    EXPECT_TRUE(kek_archive_find_by_version(db_, user_id_, 1, &row));
    EXPECT_EQ(row.user_id, user_id_);
    EXPECT_EQ(row.kek_version, 1);
    EXPECT_EQ(row.wrapped_kek.size(), sizeof(WRAPPED_KEK));
    EXPECT_EQ(memcmp(row.wrapped_kek.data(), WRAPPED_KEK, sizeof(WRAPPED_KEK)), 0);
    EXPECT_EQ(row.salt.size(), sizeof(SALT));
    EXPECT_EQ(memcmp(row.salt.data(), SALT, sizeof(SALT)), 0);
    EXPECT_EQ(row.expires_at, "2099-12-31T23:59:59Z");
}

TEST_F(KekArchiveTest, FindNonExistentVersionReturnsFalse) {
    kek_archive_row row{};
    EXPECT_FALSE(kek_archive_find_by_version(db_, user_id_, 99, &row));
}

TEST_F(KekArchiveTest, DeleteVersion) {
    ASSERT_TRUE(kek_archive_store(db_, user_id_, 1, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                  sizeof(SALT), "2099-12-31T23:59:59Z"));

    EXPECT_TRUE(kek_archive_delete_version(db_, user_id_, 1));

    kek_archive_row row{};
    EXPECT_FALSE(kek_archive_find_by_version(db_, user_id_, 1, &row));
}

TEST_F(KekArchiveTest, DeleteNonExistentVersionReturnsFalse) {
    EXPECT_FALSE(kek_archive_delete_version(db_, user_id_, 99));
}

TEST_F(KekArchiveTest, ListForUserReturnsCorrectCount) {
    ASSERT_TRUE(kek_archive_store(db_, user_id_, 1, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                  sizeof(SALT), "2099-12-31T23:59:59Z"));
    ASSERT_TRUE(kek_archive_store(db_, user_id_, 2, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                  sizeof(SALT), "2099-12-31T23:59:59Z"));

    // One entry for user2
    ASSERT_TRUE(kek_archive_store(db_, user2_id_, 1, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                  sizeof(SALT), "2099-12-31T23:59:59Z"));

    std::vector<kek_archive_row> rows;
    EXPECT_TRUE(kek_archive_list_for_user(db_, user_id_, &rows));
    EXPECT_EQ(rows.size(), 2);
    EXPECT_EQ(rows[0].kek_version, 1);
    EXPECT_EQ(rows[1].kek_version, 2);
}

TEST_F(KekArchiveTest, ListForUserReturnsEmptyWhenNone) {
    std::vector<kek_archive_row> rows;
    EXPECT_TRUE(kek_archive_list_for_user(db_, user_id_, &rows));
    EXPECT_TRUE(rows.empty());
}

TEST_F(KekArchiveTest, DuplicateVersionRejected) {
    ASSERT_TRUE(kek_archive_store(db_, user_id_, 1, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                  sizeof(SALT), "2099-12-31T23:59:59Z"));

    // Same user and version — UNIQUE constraint violation
    EXPECT_FALSE(kek_archive_store(db_, user_id_, 1, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                   sizeof(SALT), "2099-12-31T23:59:59Z"));
}

TEST_F(KekArchiveTest, SameVersionDifferentUserAllowed) {
    ASSERT_TRUE(kek_archive_store(db_, user_id_, 1, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                  sizeof(SALT), "2099-12-31T23:59:59Z"));

    EXPECT_TRUE(kek_archive_store(db_, user2_id_, 1, WRAPPED_KEK, sizeof(WRAPPED_KEK), SALT,
                                  sizeof(SALT), "2099-12-31T23:59:59Z"));

    std::vector<kek_archive_row> rows;
    EXPECT_TRUE(kek_archive_list_for_user(db_, user2_id_, &rows));
    EXPECT_EQ(rows.size(), 1);
}

}  // namespace
}  // namespace ssm::v1

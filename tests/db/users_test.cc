#include <gtest/gtest.h>

#include <sqlcipher.h>

#include "db/database.h"
#include "db/users.h"

namespace ssm::v1 {
namespace {

static const unsigned char TEST_KEY[] = "test-key-32-bytes-for-sqlcipher!!";
static const unsigned char HASH[] =
    "$argon2id$v=19$m=65536,t=2,p=1$test-salt-here-1234$hash-value-goes-here!";

class UsersTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(db_open(":memory:", TEST_KEY, sizeof(TEST_KEY) - 1, &db_));
        ASSERT_TRUE(db_create_schema(db_));
    }

    void TearDown() override
    {
        db_close(db_);
    }

    sqlite3* db_ = nullptr;
};

TEST_F(UsersTest, CreateUser)
{
    int64_t id = 0;
    EXPECT_TRUE(users_create(db_, "alice", HASH, sizeof(HASH), &id));
    EXPECT_GT(id, 0);
}

TEST_F(UsersTest, FindByUsername)
{
    int64_t id = 0;
    ASSERT_TRUE(users_create(db_, "alice", HASH, sizeof(HASH), &id));

    user_row row{};
    EXPECT_TRUE(users_find_by_username(db_, "alice", &row));
    EXPECT_EQ(row.id, id);
    EXPECT_EQ(row.password_hash.size(), sizeof(HASH));
}

TEST_F(UsersTest, FindNonExistentReturnsFalse)
{
    user_row row{};
    EXPECT_FALSE(users_find_by_username(db_, "nobody", &row));
}

TEST_F(UsersTest, DuplicateUsernameFails)
{
    int64_t id1 = 0, id2 = 0;
    EXPECT_TRUE(users_create(db_, "alice", HASH, sizeof(HASH), &id1));
    EXPECT_FALSE(users_create(db_, "alice", HASH, sizeof(HASH), &id2));
}

TEST_F(UsersTest, DeleteUser)
{
    int64_t id = 0;
    ASSERT_TRUE(users_create(db_, "alice", HASH, sizeof(HASH), &id));

    EXPECT_TRUE(users_delete(db_, id));
    EXPECT_FALSE(users_find_by_username(db_, "alice", nullptr));
}

TEST_F(UsersTest, DeleteNonExistentReturnsFalse)
{
    EXPECT_FALSE(users_delete(db_, 999));
}

TEST_F(UsersTest, MultipleUsers)
{
    int64_t id1 = 0, id2 = 0;
    EXPECT_TRUE(users_create(db_, "alice", HASH, sizeof(HASH), &id1));
    EXPECT_TRUE(users_create(db_, "bob", HASH, sizeof(HASH), &id2));
    EXPECT_NE(id1, id2);
}

} // namespace
} // namespace ssm::v1

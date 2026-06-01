#include <gtest/gtest.h>

#include <sqlcipher.h>

#include "db/database.h"

namespace ssm::v1 {
namespace {

static const unsigned char TEST_KEY[] = "test-key-32-bytes-for-sqlcipher!!";

class DatabaseTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(db_open(":memory:", TEST_KEY, sizeof(TEST_KEY) - 1, &db_));
        ASSERT_NE(db_, nullptr);
    }

    void TearDown() override
    {
        db_close(db_);
    }

    sqlite3* db_ = nullptr;
};

TEST_F(DatabaseTest, OpenAndClose) {}

TEST_F(DatabaseTest, CreateSchema)
{
    EXPECT_TRUE(db_create_schema(db_));
}

TEST_F(DatabaseTest, TablesExistAfterSchema)
{
    ASSERT_TRUE(db_create_schema(db_));

    auto check_table = [&](const char* name) -> bool
    {
        const char* sql =
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='table' AND name=?";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;

        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        bool found = (sqlite3_step(stmt) == SQLITE_ROW &&
                      sqlite3_column_int(stmt, 0) == 1);
        sqlite3_finalize(stmt);
        return found;
    };

    EXPECT_TRUE(check_table("users"));
    EXPECT_TRUE(check_table("kek_metadata"));
    EXPECT_TRUE(check_table("secrets"));
}

TEST_F(DatabaseTest, SchemaIdempotent)
{
    EXPECT_TRUE(db_create_schema(db_));
    EXPECT_TRUE(db_create_schema(db_));
    EXPECT_TRUE(db_create_schema(db_));
}

TEST_F(DatabaseTest, ForeignKeysEnabled)
{
    ASSERT_TRUE(db_create_schema(db_));

    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(db_, "PRAGMA foreign_keys", -1, &stmt, nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    EXPECT_EQ(sqlite3_column_int(stmt, 0), 1);
    sqlite3_finalize(stmt);
}

TEST(DatabaseOpenTest, NullPathFails)
{
    sqlite3* db = nullptr;
    EXPECT_FALSE(db_open(nullptr, TEST_KEY, sizeof(TEST_KEY) - 1, &db));
}

TEST(DatabaseOpenTest, NullKeyFails)
{
    sqlite3* db = nullptr;
    EXPECT_FALSE(db_open(":memory:", nullptr, 0, &db));
}

} // namespace
} // namespace ssm::v1

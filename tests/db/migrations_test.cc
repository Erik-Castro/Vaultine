#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>

#include "db/database.h"
#include "db/migrations.h"

namespace ssm::v1 {
namespace {

class MigrationTest : public ::testing::Test {
protected:
    sqlite3* db_ = nullptr;

    void SetUp() override {
        ASSERT_TRUE(db_open(":memory:", nullptr, 0, &db_));
        ASSERT_TRUE(db_create_schema(db_));
    }

    void TearDown() override {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }
};

TEST_F(MigrationTest, FreshSchemaVersion) {
    int version = db_get_version(db_);
    EXPECT_EQ(version, 1);
}

TEST_F(MigrationTest, MigrateToLatest) {
    EXPECT_TRUE(db_migrate(db_));
    EXPECT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);
}

TEST_F(MigrationTest, AlreadyAtLatestIsNoop) {
    EXPECT_TRUE(db_migrate(db_));
    int v = db_get_version(db_);
    EXPECT_TRUE(db_migrate(db_));
    EXPECT_EQ(db_get_version(db_), v);
}

TEST_F(MigrationTest, MigrationCreatesIndex) {
    ASSERT_TRUE(db_migrate(db_));

    // Verify the index exists
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(
        db_, "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_secrets_user_id'",
        -1, &stmt, nullptr);
    ASSERT_EQ(rc, SQLITE_OK);
    EXPECT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    sqlite3_finalize(stmt);
}

TEST_F(MigrationTest, Rollback) {
    ASSERT_TRUE(db_migrate(db_));
    ASSERT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);

    EXPECT_TRUE(db_rollback(db_, 1));
    EXPECT_EQ(db_get_version(db_), 1);

    // Verify the index was dropped
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(
        db_, "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_secrets_user_id'",
        -1, &stmt, nullptr);
    ASSERT_EQ(rc, SQLITE_OK);
    EXPECT_EQ(sqlite3_step(stmt), SQLITE_DONE);  // no rows
    sqlite3_finalize(stmt);
}

TEST_F(MigrationTest, RollbackFromVersion4To1) {
    ASSERT_TRUE(db_migrate(db_));
    ASSERT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);

    EXPECT_TRUE(db_rollback(db_, 1));
    EXPECT_EQ(db_get_version(db_), 1);
}

TEST_F(MigrationTest, MigrationToV4CreatesKekArchiveTable) {
    ASSERT_TRUE(db_migrate(db_));
    ASSERT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);

    // Verify kek_archive table exists
    auto check_table = [&](const char* name) -> bool {
        const char* sql = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        bool found = (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1);
        sqlite3_finalize(stmt);
        return found;
    };
    EXPECT_TRUE(check_table("kek_archive"));

    // Verify secrets has kek_version column
    auto has_column = [&](const char* table, const char* column) -> bool {
        const char* sql = "SELECT count(*) FROM pragma_table_info(?) WHERE name=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;
        sqlite3_bind_text(stmt, 1, table, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, column, -1, SQLITE_TRANSIENT);
        bool found = (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1);
        sqlite3_finalize(stmt);
        return found;
    };
    EXPECT_TRUE(has_column("secrets", "kek_version"));
}

TEST_F(MigrationTest, RollbackFromV4RemovesKekArchive) {
    ASSERT_TRUE(db_migrate(db_));
    ASSERT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);

    // Rollback to v2 (past the v3→v4 migration)
    ASSERT_TRUE(db_rollback(db_, 2));
    ASSERT_EQ(db_get_version(db_), 2);

    // Verify kek_archive is dropped
    auto check_table = [&](const char* name) -> bool {
        const char* sql = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        bool found = (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1);
        sqlite3_finalize(stmt);
        return found;
    };
    EXPECT_FALSE(check_table("kek_archive"));

    // Verify kek_version column is removed
    auto has_column = [&](const char* table, const char* column) -> bool {
        const char* sql = "SELECT count(*) FROM pragma_table_info(?) WHERE name=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;
        sqlite3_bind_text(stmt, 1, table, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, column, -1, SQLITE_TRANSIENT);
        bool found = (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1);
        sqlite3_finalize(stmt);
        return found;
    };
    EXPECT_FALSE(has_column("secrets", "kek_version"));
}

TEST_F(MigrationTest, MigrateFromV2ToV4Roundtrip) {
    // Start at v1 (fresh schema), migrate to v2 manually
    ASSERT_TRUE(db_migrate(db_));
    ASSERT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);

    // Rollback to v2
    ASSERT_TRUE(db_rollback(db_, 2));
    ASSERT_EQ(db_get_version(db_), 2);

    // Re-run migration from v2 to v4
    EXPECT_TRUE(db_migrate(db_));
    EXPECT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);

    // Verify kek_archive exists
    auto check_table = [&](const char* name) -> bool {
        const char* sql = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return false;
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        bool found = (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 1);
        sqlite3_finalize(stmt);
        return found;
    };
    EXPECT_TRUE(check_table("kek_archive"));
}

TEST_F(MigrationTest, RollbackMigrateRoundtrip) {
    // 1 → latest
    ASSERT_TRUE(db_migrate(db_));
    ASSERT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);

    // latest → 1
    ASSERT_TRUE(db_rollback(db_, 1));
    ASSERT_EQ(db_get_version(db_), 1);

    // 1 → latest again
    EXPECT_TRUE(db_migrate(db_));
    EXPECT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);
}

TEST_F(MigrationTest, NullDb) {
    EXPECT_FALSE(db_migrate(nullptr));
    EXPECT_FALSE(db_rollback(nullptr, 1));
    EXPECT_EQ(db_get_version(nullptr), -1);
    EXPECT_FALSE(db_set_version(nullptr, 1));
}

TEST_F(MigrationTest, RollbackToSameVersionIsNoop) {
    ASSERT_TRUE(db_migrate(db_));
    ASSERT_EQ(db_get_version(db_), SSM_SCHEMA_VERSION);
    EXPECT_FALSE(db_rollback(db_, SSM_SCHEMA_VERSION));
}

}  // namespace
}  // namespace ssm::v1

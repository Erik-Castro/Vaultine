#include "db/migrations.h"

#include <cstdio>
#include <cstring>

namespace ssm::v1 {

const std::array<Migration, 2> migrations = {{
    {1, 2,
     "CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id);",
     "DROP INDEX IF EXISTS idx_secrets_user_id;"},
    {2, 3,
     "CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_unique_name ON secrets(user_id, name);",
     "DROP INDEX IF EXISTS idx_secrets_unique_name;"},
}};

int db_get_version(sqlite3* db) {
    if (!db)
        return -1;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nullptr) != SQLITE_OK)
        return -1;
    int version = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        version = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return version;
}

bool db_set_version(sqlite3* db, int version) {
    if (!db)
        return false;
    char sql[64];
    std::snprintf(sql, sizeof(sql), "PRAGMA user_version = %d", version);
    char* err = nullptr;
    bool ok = sqlite3_exec(db, sql, nullptr, nullptr, &err) == SQLITE_OK;
    sqlite3_free(err);
    return ok;
}

bool db_migrate(sqlite3* db) {
    if (!db)
        return false;

    int current = db_get_version(db);
    if (current < 0)
        return false;

    // Version 0 means the schema exists but was created before migration support
    if (current == 0) {
        if (!db_set_version(db, 1))
            return false;
        current = 1;
    }

    if (current >= SSM_SCHEMA_VERSION)
        return true;

    // Apply pending migrations sequentially (ordered array)
    for (size_t i = 0; i < migrations.size(); ++i) {
        if (migrations[i].from_version != current)
            continue;

        char* err = nullptr;
        if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, &err) != SQLITE_OK) {
            sqlite3_free(err);
            return false;
        }

        if (sqlite3_exec(db, migrations[i].sql, nullptr, nullptr, &err) != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            sqlite3_free(err);
            return false;
        }

        if (!db_set_version(db, migrations[i].to_version)) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }

        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, &err) != SQLITE_OK) {
            sqlite3_free(err);
            return false;
        }

        current = migrations[i].to_version;
    }

    return current == SSM_SCHEMA_VERSION;
}

bool db_rollback(sqlite3* db, int target_version) {
    if (!db)
        return false;

    int current = db_get_version(db);
    if (current < 0 || current <= target_version)
        return false;

    for (int i = static_cast<int>(migrations.size()) - 1; i >= 0; --i) {
        if (migrations[i].to_version != current)
            continue;
        if (!migrations[i].rollback_sql)
            return false;

        char* err = nullptr;
        if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, &err) != SQLITE_OK) {
            sqlite3_free(err);
            return false;
        }

        if (sqlite3_exec(db, migrations[i].rollback_sql, nullptr, nullptr, &err) != SQLITE_OK) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            sqlite3_free(err);
            return false;
        }

        if (!db_set_version(db, migrations[i].from_version)) {
            sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }

        if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, &err) != SQLITE_OK) {
            sqlite3_free(err);
            return false;
        }

        current = migrations[i].from_version;
        if (current == target_version)
            return true;
    }

    return false;
}

}  // namespace ssm::v1

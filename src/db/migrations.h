#pragma once

#include <sqlcipher.h>

#include <array>
#include <cstddef>

namespace ssm::v1 {

// Current schema version
constexpr int SSM_SCHEMA_VERSION = 3;

// Get current schema version from DB (PRAGMA user_version)
int db_get_version(sqlite3* db);

// Set schema version
bool db_set_version(sqlite3* db, int version);

// Apply all pending migrations (from current to latest)
bool db_migrate(sqlite3* db);

// Rollback one migration step (from current down)
bool db_rollback(sqlite3* db, int target_version);

// Migration entry
struct Migration {
    int from_version;
    int to_version;
    const char* sql;
    const char* rollback_sql;  // null = irreversible
};

extern const std::array<Migration, 2> migrations;

}  // namespace ssm::v1

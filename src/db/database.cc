#include "db/database.h"
#include "db/migrations.h"

#include <cstdio>
#include <string>

namespace ssm::v1 {

static bool sqlcipher_is_present(sqlite3* db) {
    auto* stmt = static_cast<sqlite3_stmt*>(nullptr);
    int rc = sqlite3_prepare_v2(db, "PRAGMA cipher_version", -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
        return false;
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW;
}

static bool set_key_via_pragma(sqlite3* db, const unsigned char* key, size_t key_len) {
    std::string sql = "PRAGMA key = x'";
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < key_len; ++i) {
        sql += hex[key[i] >> 4];
        sql += hex[key[i] & 0x0f];
    }
    sql += "';";

    char* err = nullptr;
    bool ok = (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK);
    sqlite3_free(err);
    return ok;
}

bool db_open(const char* path, const unsigned char* key, size_t key_len, sqlite3** out) {
    if (!path || !out)
        return false;

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;

    if (sqlite3_open_v2(path, out, flags, nullptr) != SQLITE_OK)
        return false;

    if (sqlcipher_is_present(*out)) {
        if (!key || key_len == 0) {
            sqlite3_close(*out);
            *out = nullptr;
            return false;
        }
        if (!set_key_via_pragma(*out, key, key_len)) {
            sqlite3_close(*out);
            *out = nullptr;
            return false;
        }
    }

    return true;
}

void db_close(sqlite3* db) {
    if (db)
        sqlite3_close(db);
}

bool db_create_schema(sqlite3* db) {
    if (!db)
        return false;

    const char* sql =
        "PRAGMA foreign_keys = ON;"
        "PRAGMA journal_mode = WAL;"

        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT UNIQUE NOT NULL,"
        "  password_hash BLOB NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))"
        ");"

        "CREATE TABLE IF NOT EXISTS kek_metadata ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        "  wrapped_kek BLOB NOT NULL,"
        "  salt BLOB NOT NULL,"
        "  expires_at TEXT NOT NULL,"
        "  kek_version INTEGER NOT NULL DEFAULT 1,"
        "  UNIQUE(user_id)"
        ");"

        "CREATE TABLE IF NOT EXISTS secrets ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        "  name TEXT,"
        "  private_key BLOB NOT NULL,"
        "  public_key BLOB,"
        "  nonce BLOB NOT NULL,"
        "  tag BLOB NOT NULL,"
        "  description TEXT,"
        "  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),"
        "  UNIQUE(user_id, name)"
        ");"

        "CREATE TABLE IF NOT EXISTS audit_log ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  user_id INTEGER,"
        "  username TEXT NOT NULL,"
        "  operation TEXT NOT NULL,"
        "  operation_target TEXT,"
        "  details TEXT,"
        "  result TEXT NOT NULL,"
        "  timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))"
        ");"

        "CREATE TABLE IF NOT EXISTS kek_archive ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        "  kek_version INTEGER NOT NULL,"
        "  wrapped_kek BLOB NOT NULL,"
        "  salt BLOB NOT NULL,"
        "  expires_at TEXT NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),"
        "  UNIQUE(user_id, kek_version)"
        ");";

    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return false;
    }

    // Set schema version if this is a fresh or pre-migration database
    if (db_get_version(db) == 0)
        db_set_version(db, 1);

    return true;
}

}  // namespace ssm::v1

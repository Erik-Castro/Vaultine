#include "db/users.h"

#include <cstring>

namespace ssm::v1 {

bool users_create(sqlite3* db, const char* username, const unsigned char* password_hash,
                  size_t hash_len, int64_t* out_id) {
    if (!db || !username || !password_hash || !out_id)
        return false;

    const char* sql = "INSERT INTO users (username, password_hash) VALUES (?, ?)";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_blob(stmt, 2, password_hash, static_cast<int>(hash_len),
                              SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;

        *out_id = sqlite3_last_insert_rowid(db);
        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool users_find_by_username(sqlite3* db, const char* username, user_row* out) {
    if (!db || !username || !out)
        return false;

    const char* sql = "SELECT id, password_hash FROM users WHERE username = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        if (sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_step(stmt) != SQLITE_ROW)
            break;

        out->id = sqlite3_column_int64(stmt, 0);

        auto* blob = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 1));
        auto blob_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 1));
        out->password_hash.assign(blob, blob + blob_len);

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool users_delete(sqlite3* db, int64_t user_id) {
    if (!db)
        return false;

    const char* sql = "DELETE FROM users WHERE id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);
        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;
        ok = sqlite3_changes(db) > 0;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

}  // namespace ssm::v1

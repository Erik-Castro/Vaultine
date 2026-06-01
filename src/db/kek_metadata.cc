#include "db/kek_metadata.h"

namespace ssm::v1 {

bool kek_store(sqlite3* db, int64_t user_id, const unsigned char* wrapped_kek,
               size_t wrapped_kek_len, const unsigned char* salt, size_t salt_len,
               const char* expires_at) {
    if (!db || !wrapped_kek || !salt || !expires_at)
        return false;

    const char* sql =
        "INSERT INTO kek_metadata (user_id, wrapped_kek, salt, expires_at) "
        "VALUES (?, ?, ?, ?)";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);

        if (sqlite3_bind_blob(stmt, 2, wrapped_kek, static_cast<int>(wrapped_kek_len),
                              SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_blob(stmt, 3, salt, static_cast<int>(salt_len), SQLITE_TRANSIENT) !=
            SQLITE_OK)
            break;

        if (sqlite3_bind_text(stmt, 4, expires_at, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool kek_find_by_user(sqlite3* db, int64_t user_id, kek_row* out) {
    if (!db || !out)
        return false;

    const char* sql =
        "SELECT id, user_id, wrapped_kek, salt, expires_at, kek_version "
        "FROM kek_metadata WHERE user_id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);

        if (sqlite3_step(stmt) != SQLITE_ROW)
            break;

        out->id = sqlite3_column_int64(stmt, 0);
        out->user_id = sqlite3_column_int64(stmt, 1);

        auto* wk = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 2));
        auto wk_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 2));
        out->wrapped_kek.assign(wk, wk + wk_len);

        auto* s = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 3));
        auto s_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 3));
        out->salt.assign(s, s + s_len);

        auto* ea = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        out->expires_at.assign(ea);

        out->kek_version = sqlite3_column_int64(stmt, 5);

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool kek_update(sqlite3* db, int64_t user_id, const unsigned char* wrapped_kek,
                size_t wrapped_kek_len, const unsigned char* salt, size_t salt_len,
                const char* expires_at, int64_t expected_version) {
    if (!db || !wrapped_kek || !salt || !expires_at)
        return false;
    if (expected_version < 1)
        return false;

    const char* sql =
        "UPDATE kek_metadata SET wrapped_kek = ?, salt = ?, expires_at = ?, "
        "kek_version = kek_version + 1 "
        "WHERE user_id = ? AND kek_version = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        if (sqlite3_bind_blob(stmt, 1, wrapped_kek, static_cast<int>(wrapped_kek_len),
                               SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_blob(stmt, 2, salt, static_cast<int>(salt_len), SQLITE_TRANSIENT) !=
            SQLITE_OK)
            break;

        if (sqlite3_bind_text(stmt, 3, expires_at, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        sqlite3_bind_int64(stmt, 4, user_id);
        sqlite3_bind_int64(stmt, 5, expected_version);

        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;

        if (sqlite3_changes(db) == 0)
            break;

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool kek_delete(sqlite3* db, int64_t user_id) {
    if (!db)
        return false;

    const char* sql = "DELETE FROM kek_metadata WHERE user_id = ?";

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

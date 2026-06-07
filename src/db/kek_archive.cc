#include "db/kek_archive.h"

namespace ssm::v1 {

bool kek_archive_store(sqlite3* db, int64_t user_id, int64_t kek_version,
                       const unsigned char* wrapped_kek, size_t wrapped_kek_len,
                       const unsigned char* salt, size_t salt_len, const char* expires_at) {
    if (!db || !wrapped_kek || !salt || !expires_at)
        return false;
    if (kek_version < 1)
        return false;

    const char* sql =
        "INSERT INTO kek_archive (user_id, kek_version, wrapped_kek, salt, expires_at) "
        "VALUES (?, ?, ?, ?, ?)";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);
        sqlite3_bind_int64(stmt, 2, kek_version);

        if (sqlite3_bind_blob(stmt, 3, wrapped_kek, static_cast<int>(wrapped_kek_len),
                               SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_blob(stmt, 4, salt, static_cast<int>(salt_len),
                               SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_text(stmt, 5, expires_at, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool kek_archive_find_by_version(sqlite3* db, int64_t user_id, int64_t kek_version,
                                 kek_archive_row* out) {
    if (!db || !out)
        return false;

    const char* sql =
        "SELECT id, user_id, kek_version, wrapped_kek, salt, expires_at, created_at "
        "FROM kek_archive WHERE user_id = ? AND kek_version = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);
        sqlite3_bind_int64(stmt, 2, kek_version);

        if (sqlite3_step(stmt) != SQLITE_ROW)
            break;

        out->id = sqlite3_column_int64(stmt, 0);
        out->user_id = sqlite3_column_int64(stmt, 1);
        out->kek_version = sqlite3_column_int64(stmt, 2);

        auto* wk = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 3));
        auto wk_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 3));
        out->wrapped_kek.assign(wk, wk + wk_len);

        auto* s = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 4));
        auto s_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 4));
        out->salt.assign(s, s + s_len);

        auto* ea = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        out->expires_at.assign(ea ? ea : "");

        auto* ca = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        out->created_at.assign(ca ? ca : "");

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool kek_archive_delete_version(sqlite3* db, int64_t user_id, int64_t kek_version) {
    if (!db)
        return false;

    const char* sql = "DELETE FROM kek_archive WHERE user_id = ? AND kek_version = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);
        sqlite3_bind_int64(stmt, 2, kek_version);

        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;

        ok = sqlite3_changes(db) > 0;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool kek_archive_list_for_user(sqlite3* db, int64_t user_id,
                               std::vector<kek_archive_row>* out) {
    if (!db || !out)
        return false;

    const char* sql =
        "SELECT id, user_id, kek_version, wrapped_kek, salt, expires_at, created_at "
        "FROM kek_archive WHERE user_id = ? ORDER BY kek_version";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;
    out->clear();
    out->reserve(64);

    do {
        sqlite3_bind_int64(stmt, 1, user_id);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            kek_archive_row row;
            row.id = sqlite3_column_int64(stmt, 0);
            row.user_id = sqlite3_column_int64(stmt, 1);
            row.kek_version = sqlite3_column_int64(stmt, 2);

            auto* wk = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 3));
            auto wk_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 3));
            row.wrapped_kek.assign(wk, wk + wk_len);

            auto* s = static_cast<const unsigned char*>(sqlite3_column_blob(stmt, 4));
            auto s_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 4));
            row.salt.assign(s, s + s_len);

            auto* ea = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            row.expires_at.assign(ea ? ea : "");

            auto* ca = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            row.created_at.assign(ca ? ca : "");

            out->push_back(std::move(row));
        }

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

}  // namespace ssm::v1

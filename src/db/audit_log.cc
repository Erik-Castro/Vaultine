#include "db/audit_log.h"

#include <cstring>
#include <string>
#include <vector>

namespace ssm::v1 {

bool audit_log_write(sqlite3* db, int64_t user_id, const char* username, const char* operation,
                     const char* result, const char* operation_target, const char* details) {
    if (!db || !username || !operation || !result)
        return false;

    const char* sql =
        "INSERT INTO audit_log (user_id, username, operation, operation_target, details, result) "
        "VALUES (?, ?, ?, ?, ?, ?)";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;
    do {
        if (user_id > 0)
            sqlite3_bind_int64(stmt, 1, user_id);
        else
            sqlite3_bind_null(stmt, 1);

        if (sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_text(stmt, 3, operation, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (operation_target)
            sqlite3_bind_text(stmt, 4, operation_target, -1, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(stmt, 4);

        if (details)
            sqlite3_bind_text(stmt, 5, details, -1, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(stmt, 5);

        if (sqlite3_bind_text(stmt, 6, result, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool audit_log_query(sqlite3* db, const char* username, const char* operation, const char* result,
                     int64_t limit, int64_t offset, std::vector<audit_entry>* out) {
    if (!db || !out)
        return false;

    std::string sql =
        "SELECT id, user_id, username, operation, "
        "COALESCE(operation_target,''), COALESCE(details,''), "
        "result, timestamp FROM audit_log WHERE 1=1";

    if (username)
        sql += " AND username = ?";
    if (operation)
        sql += " AND operation = ?";
    if (result)
        sql += " AND result = ?";

    sql += " ORDER BY id DESC LIMIT ? OFFSET ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;
    do {
        int idx = 1;
        if (username)
            sqlite3_bind_text(stmt, idx++, username, -1, SQLITE_TRANSIENT);
        if (operation)
            sqlite3_bind_text(stmt, idx++, operation, -1, SQLITE_TRANSIENT);
        if (result)
            sqlite3_bind_text(stmt, idx++, result, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, idx++, limit);
        sqlite3_bind_int64(stmt, idx++, offset);

        out->clear();
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            audit_entry e;
            e.id = sqlite3_column_int64(stmt, 0);
            e.user_id = sqlite3_column_int64(stmt, 1);
            auto col2 = sqlite3_column_text(stmt, 2);
            e.username = col2 ? reinterpret_cast<const char*>(col2) : "";
            auto col3 = sqlite3_column_text(stmt, 3);
            e.operation = col3 ? reinterpret_cast<const char*>(col3) : "";
            auto col4 = sqlite3_column_text(stmt, 4);
            e.operation_target = col4 ? reinterpret_cast<const char*>(col4) : "";
            auto col5 = sqlite3_column_text(stmt, 5);
            e.details = col5 ? reinterpret_cast<const char*>(col5) : "";
            auto col6 = sqlite3_column_text(stmt, 6);
            e.result = col6 ? reinterpret_cast<const char*>(col6) : "";
            auto col7 = sqlite3_column_text(stmt, 7);
            e.timestamp = col7 ? reinterpret_cast<const char*>(col7) : "";
            out->push_back(std::move(e));
        }

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool audit_log_prune(sqlite3* db, int days) {
    if (!db || days <= 0)
        return false;

    const char* sql =
        "DELETE FROM audit_log WHERE timestamp < "
        "strftime('%Y-%m-%dT%H:%M:%SZ','now', ?)";

    char modifier[64];
    std::snprintf(modifier, sizeof(modifier), "-%d days", days);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, modifier, -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

}  // namespace ssm::v1

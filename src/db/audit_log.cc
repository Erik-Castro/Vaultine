#include "db/audit_log.h"

namespace ssm::v1 {

bool audit_log_write(sqlite3* db, int64_t user_id, const char* username,
                     const char* operation, const char* result,
                     const char* operation_target, const char* details) {
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

}  // namespace ssm::v1

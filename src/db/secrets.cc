#include "db/secrets.h"

#include <cstring>

namespace ssm::v1 {

static bool read_secret_row(sqlite3_stmt* stmt, secret_row* out)
{
    out->id     = sqlite3_column_int64(stmt, 0);
    out->user_id = sqlite3_column_int64(stmt, 1);

    auto* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    out->name = name ? name : "";

    auto* pk = static_cast<const unsigned char*>(
        sqlite3_column_blob(stmt, 3));
    auto pk_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 3));
    out->private_key.assign(pk, pk + pk_len);

    auto* pub = static_cast<const unsigned char*>(
        sqlite3_column_blob(stmt, 4));
    auto pub_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 4));
    out->public_key.assign(pub, pub + pub_len);

    auto* n = static_cast<const unsigned char*>(
        sqlite3_column_blob(stmt, 5));
    auto n_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 5));
    out->nonce.assign(n, n + n_len);

    auto* t = static_cast<const unsigned char*>(
        sqlite3_column_blob(stmt, 6));
    auto t_len = static_cast<size_t>(sqlite3_column_bytes(stmt, 6));
    out->tag.assign(t, t + t_len);

    auto* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    out->description = desc ? desc : "";

    auto* ua = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
    out->updated_at = ua ? ua : "";

    return true;
}

bool secrets_store(sqlite3* db, int64_t user_id,
                   const char* name,
                   const unsigned char* private_key, size_t private_key_len,
                   const unsigned char* public_key, size_t public_key_len,
                   const unsigned char* nonce, size_t nonce_len,
                   const unsigned char* tag, size_t tag_len,
                   const char* description)
{
    if (!db || !private_key || !nonce || !tag)
        return false;

    const char* sql =
        "INSERT INTO secrets "
        "(user_id, name, private_key, public_key, nonce, tag, description) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);

        if (sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_blob(stmt, 3, private_key,
                              static_cast<int>(private_key_len),
                              SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_blob(stmt, 4, public_key,
                              static_cast<int>(public_key_len),
                              SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_blob(stmt, 5, nonce,
                              static_cast<int>(nonce_len),
                              SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_blob(stmt, 6, tag,
                              static_cast<int>(tag_len),
                              SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_bind_text(stmt, 7, description, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool secrets_find(sqlite3* db, int64_t user_id, const char* name,
                  secret_row* out)
{
    if (!db || !name || !out)
        return false;

    const char* sql =
        "SELECT id, user_id, name, private_key, public_key, nonce, tag, "
        "       description, updated_at "
        "FROM secrets WHERE user_id = ? AND name = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);

        if (sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT) != SQLITE_OK)
            break;

        if (sqlite3_step(stmt) != SQLITE_ROW)
            break;

        read_secret_row(stmt, out);
        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool secrets_delete(sqlite3* db, int64_t user_id, const char* name)
{
    if (!db || !name)
        return false;

    const char* sql =
        "DELETE FROM secrets WHERE user_id = ? AND name = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;

    do {
        sqlite3_bind_int64(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE)
            break;
        ok = sqlite3_changes(db) > 0;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

bool secrets_list(sqlite3* db, int64_t user_id,
                  std::vector<secret_row>* out)
{
    return secrets_list_for_user(db, user_id, out);
}

bool secrets_list_for_user(sqlite3* db, int64_t user_id,
                           std::vector<secret_row>* out)
{
    if (!db || !out)
        return false;

    const char* sql =
        "SELECT id, user_id, name, private_key, public_key, nonce, tag, "
        "       description, updated_at "
        "FROM secrets WHERE user_id = ? "
        "ORDER BY updated_at DESC";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    bool ok = false;
    out->clear();

    do {
        sqlite3_bind_int64(stmt, 1, user_id);

        while (sqlite3_step(stmt) == SQLITE_ROW)
        {
            secret_row row;
            read_secret_row(stmt, &row);
            out->push_back(std::move(row));
        }

        ok = true;
    } while (false);

    sqlite3_finalize(stmt);
    return ok;
}

} // namespace ssm::v1

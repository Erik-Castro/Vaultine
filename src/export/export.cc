#include "export/export.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace ssm::v1 {
namespace {

struct user_row {
    int64_t id;
    std::string username;
    std::string created_at;
};

struct secret_row {
    std::string username;
    std::string name;
    int64_t size;
    int has_pub;
    std::string description;
    std::string updated_at;
};

struct kek_row {
    std::string username;
    std::string expires_at;
    int64_t version;
};

bool query_users(sqlite3* db, std::vector<user_row>& users) {
    const char* sql = "SELECT id, username, created_at FROM users ORDER BY id";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        user_row u;
        u.id = sqlite3_column_int64(stmt, 0);
        auto* uname = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        u.username = uname ? uname : "";
        auto* cat = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        u.created_at = cat ? cat : "";
        users.push_back(std::move(u));
    }
    sqlite3_finalize(stmt);
    return true;
}

bool query_secrets(sqlite3* db, std::vector<secret_row>& secrets) {
    const char* sql =
        "SELECT u.username, s.name, length(s.private_key), "
        "  CASE WHEN s.public_key IS NULL THEN 0 ELSE 1 END, "
        "  COALESCE(s.description,''), s.updated_at "
        "FROM secrets s JOIN users u ON u.id = s.user_id ORDER BY u.id, s.name";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        secret_row s;
        auto* uname = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        s.username = uname ? uname : "";
        auto* n = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        s.name = n ? n : "";
        s.size = sqlite3_column_int64(stmt, 2);
        s.has_pub = sqlite3_column_int(stmt, 3);
        auto* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        s.description = desc ? desc : "";
        auto* ua = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        s.updated_at = ua ? ua : "";
        secrets.push_back(std::move(s));
    }
    sqlite3_finalize(stmt);
    return true;
}

bool query_keks(sqlite3* db, std::vector<kek_row>& keks) {
    const char* sql =
        "SELECT u.username, k.expires_at, k.kek_version "
        "FROM kek_metadata k JOIN users u ON u.id = k.user_id ORDER BY u.id";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        kek_row k;
        auto* uname = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        k.username = uname ? uname : "";
        auto* ea = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        k.expires_at = ea ? ea : "";
        k.version = sqlite3_column_int64(stmt, 2);
        keks.push_back(std::move(k));
    }
    sqlite3_finalize(stmt);
    return true;
}

void cb_write(const char* s, ssm_export_cb callback, void* user_data) {
    if (callback)
        callback(s, std::strlen(s), user_data);
}

void json_escape(std::string& out, const std::string& s) {
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
}

void csv_escape(std::string& out, const std::string& s) {
    bool needs_quoting = s.empty() || s.find_first_of(",\"\n\r") != std::string::npos;
    if (!needs_quoting) {
        out += s;
        return;
    }
    out += '"';
    for (char c : s) {
        if (c == '"')
            out += "\"\"";
        else
            out += c;
    }
    out += '"';
}

void emit_json_users(std::string& buf, const std::vector<user_row>& users, int redact_pii) {
    buf += "\"users\":[";
    for (size_t i = 0; i < users.size(); ++i) {
        if (i > 0) buf += ",";
        buf += "{\"username\":\"";
        if (redact_pii) {
            buf += "user_" + std::to_string(i + 1);
        } else {
            json_escape(buf, users[i].username);
        }
        buf += "\",\"created_at\":\"";
        json_escape(buf, users[i].created_at);
        buf += "\"}";
    }
    buf += "]";
}

void emit_csv_users(std::string& buf, const std::vector<user_row>& users, int redact_pii) {
    buf += "username,created_at\n";
    for (size_t i = 0; i < users.size(); ++i) {
        if (redact_pii) {
            buf += "user_" + std::to_string(i + 1);
        } else {
            csv_escape(buf, users[i].username);
        }
        buf += ",";
        csv_escape(buf, users[i].created_at);
        buf += "\n";
    }
}

void emit_json_secrets(std::string& buf, const std::vector<secret_row>& secrets, int redact_pii) {
    buf += "\"secrets\":[";
    for (size_t i = 0; i < secrets.size(); ++i) {
        if (i > 0) buf += ",";
        buf += "{\"user\":\"";
        if (redact_pii) {
            buf += "redacted";
        } else {
            json_escape(buf, secrets[i].username);
        }
        buf += "\",\"name\":\"";
        json_escape(buf, secrets[i].name);
        buf += "\",\"size\":";
        buf += std::to_string(secrets[i].size);
        buf += ",\"has_pub\":";
        buf += secrets[i].has_pub ? "true" : "false";
        buf += ",\"description\":\"";
        json_escape(buf, secrets[i].description);
        buf += "\",\"updated_at\":\"";
        json_escape(buf, secrets[i].updated_at);
        buf += "\"}";
    }
    buf += "]";
}

void emit_csv_secrets(std::string& buf, const std::vector<secret_row>& secrets, int redact_pii) {
    buf += "user,name,size,has_pub,description,updated_at\n";
    for (size_t i = 0; i < secrets.size(); ++i) {
        if (redact_pii) {
            buf += "redacted";
        } else {
            csv_escape(buf, secrets[i].username);
        }
        buf += ",";
        csv_escape(buf, secrets[i].name);
        buf += ",";
        buf += std::to_string(secrets[i].size);
        buf += ",";
        buf += secrets[i].has_pub ? "true" : "false";
        buf += ",";
        csv_escape(buf, secrets[i].description);
        buf += ",";
        csv_escape(buf, secrets[i].updated_at);
        buf += "\n";
    }
}

void emit_json_keks(std::string& buf, const std::vector<kek_row>& keks, int redact_pii) {
    buf += "\"kek_metadata\":[";
    for (size_t i = 0; i < keks.size(); ++i) {
        if (i > 0) buf += ",";
        buf += "{\"user\":\"";
        if (redact_pii) {
            buf += "redacted";
        } else {
            json_escape(buf, keks[i].username);
        }
        buf += "\",\"expires_at\":\"";
        json_escape(buf, keks[i].expires_at);
        buf += "\",\"version\":";
        buf += std::to_string(keks[i].version);
        buf += "}";
    }
    buf += "]";
}

void emit_csv_keks(std::string& buf, const std::vector<kek_row>& keks, int redact_pii) {
    buf += "user,expires_at,version\n";
    for (size_t i = 0; i < keks.size(); ++i) {
        if (redact_pii) {
            buf += "redacted";
        } else {
            csv_escape(buf, keks[i].username);
        }
        buf += ",";
        csv_escape(buf, keks[i].expires_at);
        buf += ",";
        buf += std::to_string(keks[i].version);
        buf += "\n";
    }
}

}  // anonymous namespace

ssm_status export_metadata(sqlite3* db, ssm_export_format format, int redact_pii,
                           ssm_export_cb callback, void* user_data) {
    if (!db)
        return SSM_ERR_INTERNAL;

    std::vector<user_row> users;
    std::vector<secret_row> secrets;
    std::vector<kek_row> keks;

    if (!query_users(db, users))
        return SSM_ERR_INTERNAL;
    if (!query_secrets(db, secrets))
        return SSM_ERR_INTERNAL;
    if (!query_keks(db, keks))
        return SSM_ERR_INTERNAL;

    std::string buf;
    buf.reserve(4096);

    if (format == SSM_EXPORT_JSON) {
        buf += "{";
        emit_json_users(buf, users, redact_pii);
        buf += ",";
        emit_json_secrets(buf, secrets, redact_pii);
        buf += ",";
        emit_json_keks(buf, keks, redact_pii);
        buf += "}";
    } else {
        buf += "=== users ===\n";
        emit_csv_users(buf, users, redact_pii);
        buf += "=== secrets ===\n";
        emit_csv_secrets(buf, secrets, redact_pii);
        buf += "=== kek_metadata ===\n";
        emit_csv_keks(buf, keks, redact_pii);
    }

    cb_write(buf.c_str(), callback, user_data);
    return SSM_OK;
}

}  // namespace ssm::v1

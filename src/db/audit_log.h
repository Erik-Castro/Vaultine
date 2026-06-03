#pragma once

#include <sqlcipher.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ssm::v1 {

struct audit_entry {
    int64_t id;
    int64_t user_id;
    std::string username;
    std::string operation;
    std::string operation_target;
    std::string details;
    std::string result;
    std::string timestamp;
};

bool audit_log_write(sqlite3* db, int64_t user_id, const char* username, const char* operation,
                     const char* result, const char* operation_target = nullptr,
                     const char* details = nullptr);

bool audit_log_query(sqlite3* db, const char* username, const char* operation, const char* result,
                     int64_t limit, int64_t offset, std::vector<audit_entry>* out);

bool audit_log_prune(sqlite3* db, int days);

}  // namespace ssm::v1

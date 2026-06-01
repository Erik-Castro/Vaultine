#pragma once

#include <sqlcipher.h>

#include <cstdint>

namespace ssm::v1 {

bool audit_log_write(sqlite3* db, int64_t user_id, const char* username,
                     const char* operation, const char* result,
                     const char* operation_target = nullptr,
                     const char* details = nullptr);

}  // namespace ssm::v1

#pragma once

#include <sqlcipher.h>

#include <cstddef>
#include <cstdint>

namespace ssm::v1 {

bool db_open(const char* path,
             const unsigned char* key, size_t key_len,
             sqlite3** out);

void db_close(sqlite3* db);

bool db_create_schema(sqlite3* db);

} // namespace ssm::v1

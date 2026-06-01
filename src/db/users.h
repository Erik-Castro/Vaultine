#pragma once

#include <sqlcipher.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ssm::v1 {

struct user_row
{
    int64_t id;
    std::vector<unsigned char> password_hash;
};

bool users_create(sqlite3* db, const char* username,
                  const unsigned char* password_hash, size_t hash_len,
                  int64_t* out_id);

bool users_find_by_username(sqlite3* db, const char* username,
                            user_row* out);

bool users_delete(sqlite3* db, int64_t user_id);

} // namespace ssm::v1

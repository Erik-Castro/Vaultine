#pragma once

#include <sqlcipher.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ssm::v1 {

struct kek_row {
    int64_t id;
    int64_t user_id;
    std::vector<unsigned char> wrapped_kek;
    std::vector<unsigned char> salt;
    std::string expires_at;
};

bool kek_store(sqlite3* db, int64_t user_id, const unsigned char* wrapped_kek,
               size_t wrapped_kek_len, const unsigned char* salt, size_t salt_len,
               const char* expires_at);

bool kek_find_by_user(sqlite3* db, int64_t user_id, kek_row* out);

bool kek_update(sqlite3* db, int64_t user_id, const unsigned char* wrapped_kek,
                size_t wrapped_kek_len, const unsigned char* salt, size_t salt_len,
                const char* expires_at);

bool kek_delete(sqlite3* db, int64_t user_id);

}  // namespace ssm::v1

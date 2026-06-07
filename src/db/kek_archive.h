#pragma once

#include <sqlcipher.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ssm::v1 {

struct kek_archive_row {
    int64_t id;
    int64_t user_id;
    int64_t kek_version;
    std::vector<unsigned char> wrapped_kek;
    std::vector<unsigned char> salt;
    std::string expires_at;
    std::string created_at;
};

bool kek_archive_store(sqlite3* db, int64_t user_id, int64_t kek_version,
                       const unsigned char* wrapped_kek, size_t wrapped_kek_len,
                       const unsigned char* salt, size_t salt_len, const char* expires_at);

bool kek_archive_find_by_version(sqlite3* db, int64_t user_id, int64_t kek_version,
                                 kek_archive_row* out);

bool kek_archive_delete_version(sqlite3* db, int64_t user_id, int64_t kek_version);

bool kek_archive_list_for_user(sqlite3* db, int64_t user_id,
                               std::vector<kek_archive_row>* out);

}  // namespace ssm::v1

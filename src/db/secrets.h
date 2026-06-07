#pragma once

#include <sqlcipher.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ssm::v1 {

struct secret_row {
    int64_t id;
    int64_t user_id;
    std::string name;
    std::vector<unsigned char> private_key;
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> tag;
    std::string description;
    std::string updated_at;
    int64_t kek_version = 1;
};

bool secrets_store(sqlite3* db, int64_t user_id, const char* name, const unsigned char* private_key,
                   size_t private_key_len, const unsigned char* public_key, size_t public_key_len,
                   const unsigned char* nonce, size_t nonce_len, const unsigned char* tag,
                   size_t tag_len, const char* description);

bool secrets_find(sqlite3* db, int64_t user_id, const char* name, secret_row* out);

bool secrets_delete(sqlite3* db, int64_t user_id, const char* name);

bool secrets_list_for_user(sqlite3* db, int64_t user_id, std::vector<secret_row>* out);

bool secrets_count_by_kek_version(sqlite3* db, int64_t user_id, int64_t kek_version,
                                  int64_t* count);

bool secrets_update_ciphertext(sqlite3* db, int64_t secret_id,
                               const unsigned char* private_key, size_t private_key_len,
                               const unsigned char* nonce, size_t nonce_len,
                               const unsigned char* tag, size_t tag_len,
                               int64_t kek_version);

}  // namespace ssm::v1

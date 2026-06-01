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
};

bool secrets_store(sqlite3* db, int64_t user_id, const char* name, const unsigned char* private_key,
                   size_t private_key_len, const unsigned char* public_key, size_t public_key_len,
                   const unsigned char* nonce, size_t nonce_len, const unsigned char* tag,
                   size_t tag_len, const char* description);

bool secrets_find(sqlite3* db, int64_t user_id, const char* name, secret_row* out);

bool secrets_delete(sqlite3* db, int64_t user_id, const char* name);

bool secrets_list(sqlite3* db, int64_t user_id, std::vector<secret_row>* out);

bool secrets_list_for_user(sqlite3* db, int64_t user_id, std::vector<secret_row>* out);

}  // namespace ssm::v1

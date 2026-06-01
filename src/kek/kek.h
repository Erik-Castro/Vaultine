#pragma once

#include <sqlcipher.h>

#include <cstddef>
#include <cstdint>

namespace ssm::v1 {

constexpr size_t KEK_KEY_LEN = 32;
constexpr size_t KEK_SALT_LEN = 16;
constexpr int KEK_DEFAULT_DAYS = 90;

bool kek_derive_wrapping_key(const unsigned char* auth_hash, size_t auth_hash_len,
                             const unsigned char* salt, size_t salt_len,
                             unsigned char* wrapping_key_out, size_t wrapping_key_len);

bool kek_generate(const unsigned char* auth_hash, size_t auth_hash_len,
                  unsigned char* wrapped_kek_out, size_t* wrapped_kek_len, unsigned char* salt_out,
                  size_t* salt_len, char* expires_at_out, size_t expires_at_size);

bool kek_unwrap(const unsigned char* wrapped_kek, size_t wrapped_kek_len,
                const unsigned char* auth_hash, size_t auth_hash_len, const unsigned char* salt,
                size_t salt_len, unsigned char* kek_out, size_t* kek_len);

bool kek_is_expired(const char* expires_at);

bool kek_expires_at(int days, char* out, size_t out_size);

bool kek_rotate(sqlite3* db, int64_t user_id, const unsigned char* auth_hash, size_t auth_hash_len);

}  // namespace ssm::v1

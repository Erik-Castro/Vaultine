#pragma once

#include <cstddef>
#include <cstdint>

namespace ssm::v1 {

bool argon2id_hash(const unsigned char* password, size_t password_len, const unsigned char* salt,
                   size_t salt_len, unsigned char* hash_out, size_t hash_len);

bool argon2id_verify(const unsigned char* password, size_t password_len, const unsigned char* hash,
                     size_t hash_len);

}  // namespace ssm::v1

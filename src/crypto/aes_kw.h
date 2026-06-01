#pragma once

#include <cstddef>
#include <cstdint>

namespace ssm::v1 {

bool aes_kw_wrap(
    const unsigned char* plaintext, size_t plaintext_len,
    const unsigned char* kek, size_t kek_len,
    unsigned char* ciphertext_out, size_t* ciphertext_len);

bool aes_kw_unwrap(
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* kek, size_t kek_len,
    unsigned char* plaintext_out, size_t* plaintext_len);

} // namespace ssm::v1

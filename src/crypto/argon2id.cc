#include "crypto/argon2id.h"

#include <sodium.h>

namespace ssm::v1 {

bool argon2id_hash(const unsigned char* password, size_t password_len,
                   unsigned char* hash_out, size_t hash_len) {
    if (hash_len < crypto_pwhash_STRBYTES)
        return false;

    return crypto_pwhash_str(reinterpret_cast<char*>(hash_out),
                             reinterpret_cast<const char*>(password), password_len,
                             crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) == 0;
}

bool argon2id_verify(const unsigned char* password, size_t password_len, const unsigned char* hash,
                     size_t hash_len) {
    if (hash_len < crypto_pwhash_STRBYTES)
        return false;

    return crypto_pwhash_str_verify(reinterpret_cast<const char*>(hash),
                                    reinterpret_cast<const char*>(password), password_len) == 0;
}

}  // namespace ssm::v1

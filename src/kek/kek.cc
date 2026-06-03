#include "kek/kek.h"

#include <sodium.h>

#include <cstring>
#include <ctime>

#include "crypto/aes_gcm.h"
#include "crypto/aes_kw.h"
#include "crypto/random.h"
#include "db/kek_metadata.h"
#include "db/secrets.h"
#include "utils/secure_memory.h"

namespace ssm::v1 {

bool kek_derive_wrapping_key(const unsigned char* auth_hash, size_t auth_hash_len,
                             const unsigned char* salt, size_t salt_len,
                             unsigned char* wrapping_key_out, size_t wrapping_key_len) {
    if (!auth_hash || !salt || !wrapping_key_out)
        return false;
    if (auth_hash_len == 0 || salt_len < KEK_SALT_LEN)
        return false;
    if (wrapping_key_len != KEK_KEY_LEN)
        return false;

    if (sodium_init() < 0)
        return false;

    return crypto_pwhash(wrapping_key_out, wrapping_key_len,
                         reinterpret_cast<const char*>(auth_hash), auth_hash_len, salt,
                         crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                         crypto_pwhash_ALG_ARGON2ID13) == 0;
}

bool kek_generate(const unsigned char* auth_hash, size_t auth_hash_len,
                  unsigned char* wrapped_kek_out, size_t* wrapped_kek_len, unsigned char* salt_out,
                  size_t* salt_len, char* expires_at_out, size_t expires_at_size) {
    if (!auth_hash || !wrapped_kek_out || !wrapped_kek_len || !salt_out || !salt_len ||
        !expires_at_out)
        return false;
    if (*salt_len < KEK_SALT_LEN)
        return false;

    secure_buffer<unsigned char> kek(KEK_KEY_LEN);
    secure_buffer<unsigned char> wrapping_key(KEK_KEY_LEN);
    if (!kek || !wrapping_key)
        return false;

    bool ok = false;
    do {
        random_bytes(kek.data(), kek.size());
        random_bytes(salt_out, KEK_SALT_LEN);
        *salt_len = KEK_SALT_LEN;

        if (!kek_derive_wrapping_key(auth_hash, auth_hash_len, salt_out, KEK_SALT_LEN,
                                     wrapping_key.data(), wrapping_key.size()))
            break;

        if (!aes_kw_wrap(kek.data(), kek.size(), wrapping_key.data(), wrapping_key.size(),
                         wrapped_kek_out, wrapped_kek_len))
            break;

        if (!kek_expires_at(KEK_DEFAULT_DAYS, expires_at_out, expires_at_size))
            break;

        ok = true;
    } while (false);

    return ok;
}

bool kek_unwrap(const unsigned char* wrapped_kek, size_t wrapped_kek_len,
                const unsigned char* auth_hash, size_t auth_hash_len, const unsigned char* salt,
                size_t salt_len, unsigned char* kek_out, size_t* kek_len) {
    if (!wrapped_kek || !auth_hash || !salt || !kek_out || !kek_len)
        return false;
    if (salt_len < KEK_SALT_LEN)
        return false;

    secure_buffer<unsigned char> wrapping_key(KEK_KEY_LEN);
    if (!wrapping_key)
        return false;

    bool ok = false;

    do {
        if (!kek_derive_wrapping_key(auth_hash, auth_hash_len, salt, KEK_SALT_LEN,
                                     wrapping_key.data(), wrapping_key.size()))
            break;

        if (!aes_kw_unwrap(wrapped_kek, wrapped_kek_len, wrapping_key.data(),
                           wrapping_key.size(), kek_out, kek_len))
            break;

        ok = true;
    } while (false);

    return ok;
}

bool kek_is_expired(const char* expires_at) {
    if (!expires_at)
        return true;

    struct tm tm = {};
    if (!strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ", &tm))
        return true;

    time_t expiry = timegm(&tm);

    time_t now;
    time(&now);

    return now >= expiry;
}

bool kek_expires_at(int days, char* out, size_t out_size) {
    if (!out || out_size < 22)
        return false;

    time_t now;
    time(&now);

    now += static_cast<time_t>(days) * 86400;

    struct tm tm;
    gmtime_r(&now, &tm);

    strftime(out, out_size, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return true;
}

bool kek_rotate(sqlite3* db, int64_t user_id, const unsigned char* auth_hash,
                size_t auth_hash_len) {
    if (!db || !auth_hash)
        return false;

    sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);

    secure_buffer<unsigned char> wrapping_key(KEK_KEY_LEN);
    secure_buffer<unsigned char> new_kek(KEK_KEY_LEN);
    secure_buffer<unsigned char> new_wrapping_key(KEK_KEY_LEN);
    secure_buffer<unsigned char> new_salt(KEK_SALT_LEN);
    secure_buffer<unsigned char> new_wrapped(64);
    secure_buffer<unsigned char> old_kek_raw(KEK_KEY_LEN);
    if (!wrapping_key || !new_kek || !new_wrapping_key || !new_salt || !new_wrapped ||
        !old_kek_raw)
        return false;

    size_t new_wrapped_len = 0;
    char new_expires[24];

    bool ok = false;
    do {
        // --- load current KEK ---
        kek_row old_kek;
        if (!kek_find_by_user(db, user_id, &old_kek))
            break;

        size_t old_kek_len = old_kek_raw.size();
        if (!kek_unwrap(old_kek.wrapped_kek.data(), old_kek.wrapped_kek.size(), auth_hash,
                        auth_hash_len, old_kek.salt.data(), old_kek.salt.size(),
                        old_kek_raw.data(), &old_kek_len))
            break;

        // --- load all secrets ---
        std::vector<secret_row> secrets;
        if (!secrets_list_for_user(db, user_id, &secrets))
            break;

        // --- generate new KEK + salt ---
        random_bytes(new_kek.data(), new_kek.size());
        random_bytes(new_salt.data(), new_salt.size());

        if (!kek_derive_wrapping_key(auth_hash, auth_hash_len, new_salt.data(), new_salt.size(),
                                     new_wrapping_key.data(), new_wrapping_key.size()))
            break;

        if (!aes_kw_wrap(new_kek.data(), new_kek.size(), new_wrapping_key.data(),
                         new_wrapping_key.size(), new_wrapped.data(), &new_wrapped_len))
            break;

        if (!kek_expires_at(KEK_DEFAULT_DAYS, new_expires, sizeof(new_expires)))
            break;

        // --- re-encrypt each secret ---
        bool rotation_ok = true;
        for (auto& secret : secrets) {
            secure_vector<unsigned char> plain_priv(secret.private_key.size());
            if (!aes_gcm_decrypt(secret.private_key.data(), secret.private_key.size(),
                                 old_kek_raw.data(), old_kek_len, secret.nonce.data(),
                                 secret.nonce.size(), nullptr, 0, secret.tag.data(),
                                 secret.tag.size(), plain_priv.data())) {
                rotation_ok = false;
                break;
            }

            unsigned char new_nonce[AES_GCM_NONCE_LEN];
            unsigned char new_priv_tag[AES_GCM_TAG_LEN];
            random_bytes(new_nonce, sizeof(new_nonce));

            secure_vector<unsigned char> new_priv(plain_priv.size());
            if (!aes_gcm_encrypt(plain_priv.data(), plain_priv.size(), new_kek.data(),
                                 new_kek.size(), new_nonce, sizeof(new_nonce), nullptr, 0,
                                 new_priv.data(), new_priv_tag, sizeof(new_priv_tag))) {
                rotation_ok = false;
                break;
            }

            const char* sql =
                "UPDATE secrets SET private_key = ?, public_key = ?, "
                "nonce = ?, tag = ?, "
                "updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') "
                "WHERE id = ?";
            sqlite3_stmt* stmt = nullptr;
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
                rotation_ok = false;
                break;
            }

            bool step_ok = false;
            do {
                sqlite3_bind_blob(stmt, 1, new_priv.data(), static_cast<int>(new_priv.size()),
                                  SQLITE_TRANSIENT);
                if (!secret.public_key.empty())
                    sqlite3_bind_blob(stmt, 2, secret.public_key.data(),
                                      static_cast<int>(secret.public_key.size()), SQLITE_TRANSIENT);
                else
                    sqlite3_bind_null(stmt, 2);
                sqlite3_bind_blob(stmt, 3, new_nonce, sizeof(new_nonce), SQLITE_TRANSIENT);
                sqlite3_bind_blob(stmt, 4, new_priv_tag, sizeof(new_priv_tag), SQLITE_TRANSIENT);
                sqlite3_bind_int64(stmt, 5, secret.id);
                if (sqlite3_step(stmt) == SQLITE_DONE)
                    step_ok = true;
            } while (false);

            sqlite3_finalize(stmt);
            if (!step_ok) {
                rotation_ok = false;
                break;
            }
        }

        if (!rotation_ok)
            break;

        // --- update kek_metadata (increment kek_version) ---
        if (!kek_update(db, user_id, new_wrapped.data(), new_wrapped_len, new_salt.data(),
                        new_salt.size(), new_expires, old_kek.kek_version))
            break;

        ok = true;
    } while (false);

    if (ok)
        sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
    else
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);

    return ok;
}

}  // namespace ssm::v1

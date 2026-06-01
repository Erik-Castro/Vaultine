#include "ssm/ssm.h"

#include <sodium.h>

#include <cstring>
#include <new>
#include <shared_mutex>

#include "crypto/aes_gcm.h"
#include "crypto/aes_kw.h"
#include "crypto/argon2id.h"
#include "crypto/random.h"
#include "db/database.h"
#include "db/kek_metadata.h"
#include "db/secrets.h"
#include "db/users.h"
#include "kek/kek.h"
#include "utils/secure_memory.h"

using namespace ssm::v1;

struct ssm_handle {
    sqlite3* db;
    std::shared_mutex mutex;
};

ssm_status ssm_init(ssm_handle** out, const char* db_path, const unsigned char* db_key,
                    size_t db_key_len) {
    if (!out)
        return SSM_ERR_INTERNAL;

    sqlite3* db = nullptr;
    if (!db_open(db_path, db_key, db_key_len, &db))
        return SSM_ERR_INTERNAL;

    if (!db_create_schema(db)) {
        db_close(db);
        return SSM_ERR_INTERNAL;
    }

    auto* h = new (std::nothrow) ssm_handle{db};
    if (!h) {
        db_close(db);
        return SSM_ERR_INTERNAL;
    }

    *out = h;
    return SSM_OK;
}

ssm_status ssm_destroy(ssm_handle* h) {
    if (!h)
        return SSM_ERR_INTERNAL;

    {
        std::unique_lock lock(h->mutex);
        db_close(h->db);
    }
    delete h;
    return SSM_OK;
}

ssm_status ssm_user_register(ssm_handle* h, const char* username, const char* password) {
    if (!h || !username || !password)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row existing;
    if (users_find_by_username(h->db, username, &existing))
        return SSM_ERR_AUTH;

    size_t pw_len = std::strlen(password);
    size_t hash_len = crypto_pwhash_STRBYTES;
    secure_vector<unsigned char> hash(hash_len);

    if (!argon2id_hash(reinterpret_cast<const unsigned char*>(password), pw_len, nullptr, 0,
                       hash.data(), hash.size()))
        return SSM_ERR_INTERNAL;

    int64_t user_id = 0;
    if (!users_create(h->db, username, hash.data(), hash.size(), &user_id))
        return SSM_ERR_INTERNAL;

    unsigned char wrapped[64];
    size_t wrapped_len = sizeof(wrapped);
    unsigned char salt[KEK_SALT_LEN];
    size_t salt_len = sizeof(salt);
    char expires_at[24];

    if (!kek_generate(hash.data(), hash.size(), wrapped, &wrapped_len, salt, &salt_len, expires_at,
                      sizeof(expires_at)))
        return SSM_ERR_INTERNAL;

    if (!kek_store(h->db, user_id, wrapped, wrapped_len, salt, salt_len, expires_at))
        return SSM_ERR_INTERNAL;

    return SSM_OK;
}

ssm_status ssm_user_authenticate(ssm_handle* h, const char* username, const char* password,
                                 int* is_valid) {
    if (!h || !username || !password || !is_valid)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user)) {
        *is_valid = 0;
        return SSM_OK;
    }

    size_t pw_len = std::strlen(password);
    *is_valid = argon2id_verify(reinterpret_cast<const unsigned char*>(password), pw_len,
                                user.password_hash.data(), user.password_hash.size())
                    ? 1
                    : 0;

    return SSM_OK;
}

ssm_status ssm_secret_store(ssm_handle* h, const char* username, const unsigned char* private_key,
                            size_t private_key_len, const unsigned char* public_key,
                            size_t public_key_len, const char* name, const char* description) {
    if (!h || !username || !private_key || private_key_len == 0 || !name)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user))
        return SSM_ERR_AUTH;

    kek_row kek_meta;
    if (!kek_find_by_user(h->db, user.id, &kek_meta))
        return SSM_ERR_INTERNAL;

    if (kek_is_expired(kek_meta.expires_at.c_str()))
        return SSM_ERR_EXPIRED;

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);

    if (!kek_unwrap(kek_meta.wrapped_kek.data(), kek_meta.wrapped_kek.size(),
                    user.password_hash.data(), user.password_hash.size(), kek_meta.salt.data(),
                    kek_meta.salt.size(), kek_raw, &kek_len))
        return SSM_ERR_INTERNAL;

    unsigned char nonce[AES_GCM_NONCE_LEN];
    unsigned char tag[AES_GCM_TAG_LEN];
    random_bytes(nonce, sizeof(nonce));

    secure_vector<unsigned char> ciphertext(private_key_len);
    bool enc_ok = aes_gcm_encrypt(private_key, private_key_len, kek_raw, kek_len, nonce,
                                  sizeof(nonce), nullptr, 0, ciphertext.data(), tag, sizeof(tag));

    secure_erase(kek_raw, sizeof(kek_raw));

    if (!enc_ok)
        return SSM_ERR_INTERNAL;

    const unsigned char* pub_ptr = public_key_len > 0 ? public_key : nullptr;

    if (!secrets_store(h->db, user.id, name, ciphertext.data(), ciphertext.size(), pub_ptr,
                       public_key_len, nonce, sizeof(nonce), tag, sizeof(tag), description))
        return SSM_ERR_INTERNAL;

    return SSM_OK;
}

ssm_status ssm_secret_get(ssm_handle* h, const char* username, const char* name,
                          unsigned char* private_key_out, size_t* private_key_len_out,
                          unsigned char* public_key_out, size_t* public_key_len_out) {
    if (!h || !username || !name || !private_key_out || !private_key_len_out)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user))
        return SSM_ERR_AUTH;

    kek_row kek_meta;
    if (!kek_find_by_user(h->db, user.id, &kek_meta))
        return SSM_ERR_INTERNAL;

    if (kek_is_expired(kek_meta.expires_at.c_str()))
        return SSM_ERR_EXPIRED;

    secret_row secret;
    if (!secrets_find(h->db, user.id, name, &secret))
        return SSM_ERR_NOT_FOUND;

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);

    if (!kek_unwrap(kek_meta.wrapped_kek.data(), kek_meta.wrapped_kek.size(),
                    user.password_hash.data(), user.password_hash.size(), kek_meta.salt.data(),
                    kek_meta.salt.size(), kek_raw, &kek_len))
        return SSM_ERR_INTERNAL;

    if (*private_key_len_out < secret.private_key.size()) {
        *private_key_len_out = secret.private_key.size();
        secure_erase(kek_raw, sizeof(kek_raw));
        return SSM_ERR_INTERNAL;
    }

    secure_vector<unsigned char> plaintext(secret.private_key.size());
    bool dec_ok = aes_gcm_decrypt(secret.private_key.data(), secret.private_key.size(), kek_raw,
                                  kek_len, secret.nonce.data(), secret.nonce.size(), nullptr, 0,
                                  secret.tag.data(), secret.tag.size(), plaintext.data());

    secure_erase(kek_raw, sizeof(kek_raw));

    if (!dec_ok)
        return SSM_ERR_INTEGRITY;

    std::memcpy(private_key_out, plaintext.data(), secret.private_key.size());
    *private_key_len_out = secret.private_key.size();

    if (public_key_out && public_key_len_out) {
        if (!secret.public_key.empty()) {
            if (*public_key_len_out >= secret.public_key.size()) {
                std::memcpy(public_key_out, secret.public_key.data(), secret.public_key.size());
                *public_key_len_out = secret.public_key.size();
            } else {
                *public_key_len_out = secret.public_key.size();
                return SSM_ERR_INTERNAL;
            }
        } else {
            *public_key_len_out = 0;
        }
    }

    return SSM_OK;
}

ssm_status ssm_secret_delete(ssm_handle* h, const char* username, const char* name) {
    if (!h || !username || !name)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user))
        return SSM_ERR_AUTH;

    kek_row kek_meta;
    if (!kek_find_by_user(h->db, user.id, &kek_meta))
        return SSM_ERR_INTERNAL;

    if (kek_is_expired(kek_meta.expires_at.c_str()))
        return SSM_ERR_EXPIRED;

    if (!secrets_delete(h->db, user.id, name))
        return SSM_ERR_NOT_FOUND;

    return SSM_OK;
}

ssm_status ssm_secret_list(ssm_handle* h, const char* username,
                            ssm_secret_list_cb callback, void* user_data) {
    if (!h || !username || !callback)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user))
        return SSM_ERR_AUTH;

    kek_row kek_meta;
    if (!kek_find_by_user(h->db, user.id, &kek_meta))
        return SSM_ERR_INTERNAL;

    if (kek_is_expired(kek_meta.expires_at.c_str()))
        return SSM_ERR_EXPIRED;

    std::vector<secret_row> secrets;
    if (!secrets_list_for_user(h->db, user.id, &secrets))
        return SSM_ERR_INTERNAL;

    for (auto& s : secrets) {
        callback(s.name.c_str(), s.description.c_str(), s.updated_at.c_str(),
                 s.public_key.size(), user_data);
    }

    return SSM_OK;
}

ssm_status ssm_user_delete(ssm_handle* h, const char* username, const char* password) {
    if (!h || !username || !password)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user))
        return SSM_ERR_AUTH;

    size_t pw_len = std::strlen(password);
    if (!argon2id_verify(reinterpret_cast<const unsigned char*>(password), pw_len,
                         user.password_hash.data(), user.password_hash.size()))
        return SSM_ERR_AUTH;

    if (!users_delete(h->db, user.id))
        return SSM_ERR_INTERNAL;

    return SSM_OK;
}

ssm_status ssm_user_change_password(ssm_handle* h, const char* username,
                                     const char* old_password, const char* new_password) {
    if (!h || !username || !old_password || !new_password)
        return SSM_ERR_INTERNAL;
    if (std::strlen(new_password) == 0)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user))
        return SSM_ERR_AUTH;

    size_t old_len = std::strlen(old_password);
    if (!argon2id_verify(reinterpret_cast<const unsigned char*>(old_password), old_len,
                         user.password_hash.data(), user.password_hash.size()))
        return SSM_ERR_AUTH;

    // hash new password
    size_t new_hash_len = crypto_pwhash_STRBYTES;
    secure_vector<unsigned char> new_hash(new_hash_len);
    size_t new_pw_len = std::strlen(new_password);
    if (!argon2id_hash(reinterpret_cast<const unsigned char*>(new_password), new_pw_len, nullptr, 0,
                       new_hash.data(), new_hash.size()))
        return SSM_ERR_INTERNAL;

    sqlite3_exec(h->db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);

    bool ok = false;
    do {
        // update users.password_hash
        const char* update_user =
            "UPDATE users SET password_hash = ? WHERE id = ?";
        sqlite3_stmt* stmt_u = nullptr;
        if (sqlite3_prepare_v2(h->db, update_user, -1, &stmt_u, nullptr) != SQLITE_OK)
            break;
        sqlite3_bind_blob(stmt_u, 1, new_hash.data(), static_cast<int>(new_hash.size()),
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt_u, 2, user.id);
        bool user_ok = sqlite3_step(stmt_u) == SQLITE_DONE;
        sqlite3_finalize(stmt_u);
        if (!user_ok)
            break;

        // load kek_metadata
        kek_row kek_meta;
        if (!kek_find_by_user(h->db, user.id, &kek_meta))
            break;

        // unwrap KEK with old wrapping key
        unsigned char kek_raw[KEK_KEY_LEN];
        size_t kek_len = sizeof(kek_raw);
        if (!kek_unwrap(kek_meta.wrapped_kek.data(), kek_meta.wrapped_kek.size(),
                        user.password_hash.data(), user.password_hash.size(),
                        kek_meta.salt.data(), kek_meta.salt.size(),
                        kek_raw, &kek_len))
            break;

        // re-wrap with new wrapping key (same salt)
        unsigned char new_wrapped[64];
        size_t new_wrapped_len = sizeof(new_wrapped);

        unsigned char new_wrapping_key[KEK_KEY_LEN];
        bool wrap_ok = false;
        do {
            if (!kek_derive_wrapping_key(new_hash.data(), new_hash.size(),
                                         kek_meta.salt.data(), kek_meta.salt.size(),
                                         new_wrapping_key, sizeof(new_wrapping_key)))
                break;
            if (!aes_kw_wrap(kek_raw, kek_len, new_wrapping_key, sizeof(new_wrapping_key),
                             new_wrapped, &new_wrapped_len))
                break;
            wrap_ok = true;
        } while (false);
        secure_erase(kek_raw, sizeof(kek_raw));
        secure_erase(new_wrapping_key, sizeof(new_wrapping_key));

        if (!wrap_ok)
            break;

        // update wrapped_kek only (keep same salt, version, expiry)
        const char* update_kek =
            "UPDATE kek_metadata SET wrapped_kek = ? WHERE user_id = ?";
        sqlite3_stmt* stmt_k = nullptr;
        if (sqlite3_prepare_v2(h->db, update_kek, -1, &stmt_k, nullptr) != SQLITE_OK)
            break;
        sqlite3_bind_blob(stmt_k, 1, new_wrapped, static_cast<int>(new_wrapped_len),
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt_k, 2, user.id);
        bool kek_ok = sqlite3_step(stmt_k) == SQLITE_DONE;
        sqlite3_finalize(stmt_k);
        if (!kek_ok)
            break;

        ok = true;
    } while (false);

    if (ok)
        sqlite3_exec(h->db, "COMMIT", nullptr, nullptr, nullptr);
    else
        sqlite3_exec(h->db, "ROLLBACK", nullptr, nullptr, nullptr);

    return ok ? SSM_OK : SSM_ERR_INTERNAL;
}

ssm_status ssm_kek_rotate(ssm_handle* h, const char* username) {
    if (!h || !username)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user))
        return SSM_ERR_AUTH;

    if (!kek_rotate(h->db, user.id, user.password_hash.data(), user.password_hash.size()))
        return SSM_ERR_INTERNAL;

    return SSM_OK;
}

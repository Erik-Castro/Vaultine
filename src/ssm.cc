#include "ssm/ssm.h"

#include <sodium.h>

#include <cstring>
#include <new>
#include <shared_mutex>

#include "crypto/aes_gcm.h"
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

    if (!secrets_delete(h->db, user.id, name))
        return SSM_ERR_NOT_FOUND;

    return SSM_OK;
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

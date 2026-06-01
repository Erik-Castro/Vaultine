#include "ssm/ssm.h"

#include <sodium.h>

#include <cstring>
#include <ctime>
#include <new>
#include <shared_mutex>

#include "crypto/aes_gcm.h"
#include "crypto/aes_kw.h"
#include "crypto/argon2id.h"
#include "crypto/random.h"
#include "db/audit_log.h"
#include "db/database.h"
#include "db/kek_metadata.h"
#include "db/secrets.h"
#include "db/users.h"
#include "kek/kek.h"
#include "utils/secure_memory.h"

using namespace ssm::v1;

constexpr size_t SSM_CACHE_MAX = 256;

struct cache_entry {
    int64_t user_id;
    unsigned char key[KEK_KEY_LEN];
    time_t last_used;
    bool valid;
};

struct ssm_handle {
    sqlite3* db;
    std::shared_mutex mutex;
    cache_entry cache[SSM_CACHE_MAX];
    size_t cache_hits = 0;
    size_t cache_misses = 0;
};

namespace {

// Default password validator: minimum 4 characters.
ssm_status default_password_validator(const char* password, void* /*user_data*/) {
    if (!password)
        return SSM_ERR_INTERNAL;
    size_t len = std::strlen(password);
    if (len < 4)
        return SSM_ERR_INTERNAL;
    return SSM_OK;
}

ssm_password_validator g_validator = default_password_validator;
void* g_validator_user_data = nullptr;

void audit_write(sqlite3* db, const char* username, int64_t user_id,
                  const char* operation, ssm_status result,
                  const char* operation_target = nullptr,
                  const char* details = nullptr) {
    audit_log_write(db, user_id, username ? username : "",
                    operation, ssm_status_to_string(result),
                    operation_target, details);
}

bool cache_lookup(ssm_handle* h, int64_t user_id, unsigned char* out) {
    for (int i = 0; i < SSM_CACHE_MAX; ++i) {
        if (h->cache[i].valid && h->cache[i].user_id == user_id) {
            std::memcpy(out, h->cache[i].key, KEK_KEY_LEN);
            h->cache[i].last_used = std::time(nullptr);
            ++h->cache_hits;
            return true;
        }
    }
    ++h->cache_misses;
    return false;
}

void cache_insert(ssm_handle* h, int64_t user_id, const unsigned char* key) {
    int slot = -1;
    time_t oldest = std::time(nullptr) + 1;
    for (int i = 0; i < SSM_CACHE_MAX; ++i) {
        if (!h->cache[i].valid) {
            slot = i;
            break;
        }
        if (h->cache[i].last_used < oldest) {
            oldest = h->cache[i].last_used;
            slot = i;
        }
    }
    if (slot < 0) return;
    std::memcpy(h->cache[slot].key, key, KEK_KEY_LEN);
    h->cache[slot].user_id = user_id;
    h->cache[slot].last_used = std::time(nullptr);
    h->cache[slot].valid = true;
}

void cache_invalidate(ssm_handle* h, int64_t user_id) {
    for (int i = 0; i < SSM_CACHE_MAX; ++i) {
        if (h->cache[i].valid && h->cache[i].user_id == user_id) {
            secure_erase(h->cache[i].key, KEK_KEY_LEN);
            h->cache[i].valid = false;
        }
    }
}
}  // namespace

const char* ssm_status_to_string(ssm_status status) {
    switch (status) {
        case SSM_OK:        return "SSM_OK";
        case SSM_ERR_AUTH:  return "SSM_ERR_AUTH";
        case SSM_ERR_NOT_FOUND: return "SSM_ERR_NOT_FOUND";
        case SSM_ERR_EXPIRED:   return "SSM_ERR_EXPIRED";
        case SSM_ERR_INTEGRITY: return "SSM_ERR_INTEGRITY";
        case SSM_ERR_INTERNAL:  return "SSM_ERR_INTERNAL";
        default: return "SSM_ERR_UNKNOWN";
    }
}

ssm_status ssm_cache_get_stats(ssm_handle* h, ssm_cache_stats* out) {
    if (!h || !out)
        return SSM_ERR_INTERNAL;
    std::shared_lock lock(h->mutex);
    out->total_entries = SSM_CACHE_MAX;
    out->valid_entries = 0;
    for (size_t i = 0; i < SSM_CACHE_MAX; ++i)
        if (h->cache[i].valid)
            ++out->valid_entries;
    out->hit_count = h->cache_hits;
    out->miss_count = h->cache_misses;
    return SSM_OK;
}

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
        for (int i = 0; i < SSM_CACHE_MAX; ++i) {
            if (h->cache[i].valid)
                secure_erase(h->cache[i].key, KEK_KEY_LEN);
        }
        db_close(h->db);
    }
    delete h;
    return SSM_OK;
}

void ssm_set_password_validator(ssm_password_validator validator, void* user_data) {
    g_validator = validator ? validator : default_password_validator;
    g_validator_user_data = validator ? user_data : nullptr;
}

ssm_status ssm_user_register(ssm_handle* h, const char* username, const char* password) {
    if (!h || !username || !password)
        return SSM_ERR_INTERNAL;

    ssm_status pw_status = g_validator(password, g_validator_user_data);
    if (pw_status != SSM_OK)
        return pw_status;

    std::unique_lock lock(h->mutex);

    user_row existing;
    if (users_find_by_username(h->db, username, &existing)) {
        audit_write(h->db, username, 0, "user_register", SSM_ERR_AUTH,
                    nullptr, "username already exists");
        return SSM_ERR_AUTH;
    }

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

    audit_write(h->db, username, user_id, "user_register", SSM_OK);
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
        audit_write(h->db, username, 0, "user_authenticate", SSM_ERR_AUTH,
                    nullptr, "user not found");
        return SSM_OK;
    }

    size_t pw_len = std::strlen(password);
    bool pw_ok = argon2id_verify(reinterpret_cast<const unsigned char*>(password), pw_len,
                                 user.password_hash.data(), user.password_hash.size());
    *is_valid = pw_ok ? 1 : 0;

    audit_write(h->db, username, user.id, "user_authenticate",
                pw_ok ? SSM_OK : SSM_ERR_AUTH,
                nullptr, pw_ok ? nullptr : "password mismatch");
    return SSM_OK;
}

ssm_status ssm_secret_store(ssm_handle* h, const char* username, const unsigned char* private_key,
                            size_t private_key_len, const unsigned char* public_key,
                            size_t public_key_len, const char* name, const char* description) {
    if (!h || !username || !private_key || private_key_len == 0 || !name)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user)) {
        audit_write(h->db, username, 0, "secret_store", SSM_ERR_AUTH,
                    nullptr, "user not found");
        return SSM_ERR_AUTH;
    }

    kek_row kek_meta;
    if (!kek_find_by_user(h->db, user.id, &kek_meta))
        return SSM_ERR_INTERNAL;

    if (kek_is_expired(kek_meta.expires_at.c_str())) {
        audit_write(h->db, username, user.id, "secret_store", SSM_ERR_EXPIRED,
                    name, "KEK expired");
        return SSM_ERR_EXPIRED;
    }

    unsigned char wrapping_key[KEK_KEY_LEN];
    if (!cache_lookup(h, user.id, wrapping_key)) {
        if (!kek_derive_wrapping_key(user.password_hash.data(), user.password_hash.size(),
                                     kek_meta.salt.data(), kek_meta.salt.size(),
                                     wrapping_key, sizeof(wrapping_key)))
            return SSM_ERR_INTERNAL;
        cache_insert(h, user.id, wrapping_key);
    }

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    if (!aes_kw_unwrap(kek_meta.wrapped_kek.data(), kek_meta.wrapped_kek.size(),
                       wrapping_key, sizeof(wrapping_key), kek_raw, &kek_len))
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

    audit_write(h->db, username, user.id, "secret_store", SSM_OK, name);
    return SSM_OK;
}

ssm_status ssm_secret_get(ssm_handle* h, const char* username, const char* name,
                          unsigned char* private_key_out, size_t* private_key_len_out,
                          unsigned char* public_key_out, size_t* public_key_len_out) {
    if (!h || !username || !name || !private_key_out || !private_key_len_out)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user)) {
        audit_write(h->db, username, 0, "secret_get", SSM_ERR_AUTH,
                    nullptr, "user not found");
        return SSM_ERR_AUTH;
    }

    kek_row kek_meta;
    if (!kek_find_by_user(h->db, user.id, &kek_meta))
        return SSM_ERR_INTERNAL;

    if (kek_is_expired(kek_meta.expires_at.c_str())) {
        audit_write(h->db, username, user.id, "secret_get", SSM_ERR_EXPIRED,
                    name, "KEK expired");
        return SSM_ERR_EXPIRED;
    }

    secret_row secret;
    if (!secrets_find(h->db, user.id, name, &secret))
        return SSM_ERR_NOT_FOUND;

    unsigned char wrapping_key[KEK_KEY_LEN];
    if (!cache_lookup(h, user.id, wrapping_key)) {
        if (!kek_derive_wrapping_key(user.password_hash.data(), user.password_hash.size(),
                                     kek_meta.salt.data(), kek_meta.salt.size(),
                                     wrapping_key, sizeof(wrapping_key)))
            return SSM_ERR_INTERNAL;
        cache_insert(h, user.id, wrapping_key);
    }

    unsigned char kek_raw[KEK_KEY_LEN];
    size_t kek_len = sizeof(kek_raw);
    if (!aes_kw_unwrap(kek_meta.wrapped_kek.data(), kek_meta.wrapped_kek.size(),
                       wrapping_key, sizeof(wrapping_key), kek_raw, &kek_len))
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

    if (!dec_ok) {
        audit_write(h->db, username, user.id, "secret_get", SSM_ERR_INTEGRITY,
                    name, "GCM integrity check failed");
        return SSM_ERR_INTEGRITY;
    }

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

    audit_write(h->db, username, user.id, "secret_get", SSM_OK, name);
    return SSM_OK;
}

ssm_status ssm_secret_delete(ssm_handle* h, const char* username, const char* name) {
    if (!h || !username || !name)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user)) {
        audit_write(h->db, username, 0, "secret_delete", SSM_ERR_AUTH,
                    nullptr, "user not found");
        return SSM_ERR_AUTH;
    }

    kek_row kek_meta;
    if (!kek_find_by_user(h->db, user.id, &kek_meta))
        return SSM_ERR_INTERNAL;

    if (kek_is_expired(kek_meta.expires_at.c_str())) {
        audit_write(h->db, username, user.id, "secret_delete", SSM_ERR_EXPIRED,
                    name, "KEK expired");
        return SSM_ERR_EXPIRED;
    }

    if (!secrets_delete(h->db, user.id, name))
        return SSM_ERR_NOT_FOUND;

    audit_write(h->db, username, user.id, "secret_delete", SSM_OK, name);
    return SSM_OK;
}

ssm_status ssm_secret_list(ssm_handle* h, const char* username,
                            ssm_secret_list_cb callback, void* user_data) {
    if (!h || !username || !callback)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user)) {
        audit_write(h->db, username, 0, "secret_list", SSM_ERR_AUTH,
                    nullptr, "user not found");
        return SSM_ERR_AUTH;
    }

    kek_row kek_meta;
    if (!kek_find_by_user(h->db, user.id, &kek_meta))
        return SSM_ERR_INTERNAL;

    if (kek_is_expired(kek_meta.expires_at.c_str())) {
        audit_write(h->db, username, user.id, "secret_list", SSM_ERR_EXPIRED,
                    nullptr, "KEK expired");
        return SSM_ERR_EXPIRED;
    }

    std::vector<secret_row> secrets;
    if (!secrets_list_for_user(h->db, user.id, &secrets))
        return SSM_ERR_INTERNAL;

    for (auto& s : secrets) {
        callback(s.name.c_str(), s.description.c_str(), s.updated_at.c_str(),
                 s.public_key.size(), user_data);
    }

    audit_write(h->db, username, user.id, "secret_list", SSM_OK);
    return SSM_OK;
}

ssm_status ssm_user_delete(ssm_handle* h, const char* username, const char* password) {
    if (!h || !username || !password)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user)) {
        audit_write(h->db, username, 0, "user_delete", SSM_ERR_AUTH,
                    nullptr, "user not found");
        return SSM_ERR_AUTH;
    }

    size_t pw_len = std::strlen(password);
    if (!argon2id_verify(reinterpret_cast<const unsigned char*>(password), pw_len,
                         user.password_hash.data(), user.password_hash.size())) {
        audit_write(h->db, username, user.id, "user_delete", SSM_ERR_AUTH,
                    nullptr, "password mismatch");
        return SSM_ERR_AUTH;
    }

    if (!users_delete(h->db, user.id))
        return SSM_ERR_INTERNAL;

    audit_write(h->db, username, user.id, "user_delete", SSM_OK);
    return SSM_OK;
}

ssm_status ssm_user_change_password(ssm_handle* h, const char* username,
                                     const char* old_password, const char* new_password) {
    if (!h || !username || !old_password || !new_password)
        return SSM_ERR_INTERNAL;

    ssm_status pw_status = g_validator(new_password, g_validator_user_data);
    if (pw_status != SSM_OK)
        return pw_status;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user)) {
        audit_write(h->db, username, 0, "user_change_password", SSM_ERR_AUTH,
                    nullptr, "user not found");
        return SSM_ERR_AUTH;
    }

    size_t old_len = std::strlen(old_password);
    if (!argon2id_verify(reinterpret_cast<const unsigned char*>(old_password), old_len,
                         user.password_hash.data(), user.password_hash.size())) {
        audit_write(h->db, username, user.id, "user_change_password", SSM_ERR_AUTH,
                    nullptr, "password mismatch");
        return SSM_ERR_AUTH;
    }

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

    ssm_status result;
    if (ok) {
        sqlite3_exec(h->db, "COMMIT", nullptr, nullptr, nullptr);
        cache_invalidate(h, user.id);
        result = SSM_OK;
    } else {
        sqlite3_exec(h->db, "ROLLBACK", nullptr, nullptr, nullptr);
        result = SSM_ERR_INTERNAL;
    }

    audit_write(h->db, username, user.id, "user_change_password", result);
    return result;
}

ssm_status ssm_kek_rotate(ssm_handle* h, const char* username) {
    if (!h || !username)
        return SSM_ERR_INTERNAL;

    std::unique_lock lock(h->mutex);

    user_row user;
    if (!users_find_by_username(h->db, username, &user)) {
        audit_write(h->db, username, 0, "kek_rotate", SSM_ERR_AUTH,
                    nullptr, "user not found");
        return SSM_ERR_AUTH;
    }

    if (!kek_rotate(h->db, user.id, user.password_hash.data(), user.password_hash.size())) {
        audit_write(h->db, username, user.id, "kek_rotate", SSM_ERR_INTERNAL,
                    nullptr, "KEK rotation failed");
        return SSM_ERR_INTERNAL;
    }

    cache_invalidate(h, user.id);
    audit_write(h->db, username, user.id, "kek_rotate", SSM_OK, username);
    return SSM_OK;
}

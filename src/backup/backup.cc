#include "backup/backup.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <ctime>

#include "crypto/aes_gcm.h"
#include "crypto/random.h"
#include "utils/secure_memory.h"

namespace ssm::v1 {
namespace {

const char EXPECTED_MAGIC[BACKUP_MAGIC_LEN] = {'V', 'A', 'U', 'L', 'T', 'B', 'K', 'P'};

bool read_file(const char* path, unsigned char** data_out, size_t* len_out) {
    FILE* f = std::fopen(path, "rb");
    if (!f)
        return false;

    bool ok = false;
    do {
        if (std::fseek(f, 0, SEEK_END) != 0)
            break;
        long flen = std::ftell(f);
        if (flen <= 0)
            break;
        std::rewind(f);

        auto* buf = new unsigned char[static_cast<size_t>(flen)];
        if (std::fread(buf, 1, static_cast<size_t>(flen), f) != static_cast<size_t>(flen)) {
            delete[] buf;
            break;
        }
        *data_out = buf;
        *len_out = static_cast<size_t>(flen);
        ok = true;
    } while (false);

    std::fclose(f);
    return ok;
}

bool write_file(const char* path, const unsigned char* data, size_t len) {
    FILE* f = std::fopen(path, "wb");
    if (!f)
        return false;
    bool ok = std::fwrite(data, 1, len, f) == len;
    std::fclose(f);
    return ok;
}

}  // namespace

static void derive_backup_keys(const unsigned char* key, size_t key_len,
                               unsigned char* enc_key, unsigned char* auth_key) {
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, reinterpret_cast<const unsigned char*>("ssm-backup-enc"),
                              14);
    crypto_hash_sha256_update(&st, key, key_len);
    crypto_hash_sha256_final(&st, enc_key);

    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, reinterpret_cast<const unsigned char*>("ssm-backup-auth"),
                              15);
    crypto_hash_sha256_update(&st, key, key_len);
    crypto_hash_sha256_final(&st, auth_key);
}

bool backup_create(const char* src_path, const char* dst_path, const unsigned char* key,
                   size_t key_len) {
    if (!src_path || !dst_path || !key || key_len != 32)
        return false;

    unsigned char enc_key[32];
    unsigned char auth_key[32];
    derive_backup_keys(key, key_len, enc_key, auth_key);

    unsigned char* db_data = nullptr;
    size_t db_len = 0;
    if (!read_file(src_path, &db_data, &db_len))
        return false;

    bool ok = false;
    do {
        backup_header header;
        std::memcpy(header.magic, EXPECTED_MAGIC, BACKUP_MAGIC_LEN);
        header.version = BACKUP_VERSION;
        header.timestamp = static_cast<uint64_t>(std::time(nullptr));
        random_bytes(header.nonce, BACKUP_NONCE_LEN);
        std::memset(header.reserved, 0, sizeof(header.reserved));

        size_t ciphertext_len = db_len;
        auto* ciphertext = new unsigned char[ciphertext_len];
        unsigned char tag[BACKUP_TAG_LEN];

        bool enc_ok = aes_gcm_encrypt(db_data, db_len, enc_key, sizeof(enc_key),
                                       header.nonce, BACKUP_NONCE_LEN,
                                       reinterpret_cast<const unsigned char*>(&header),
                                       sizeof(header), ciphertext, tag, BACKUP_TAG_LEN);

        if (!enc_ok) {
            delete[] ciphertext;
            break;
        }

        unsigned char hmac[BACKUP_HMAC_LEN];
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, auth_key, sizeof(auth_key));
        crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char*>(&header),
                                       sizeof(header));
        crypto_auth_hmacsha256_update(&state, ciphertext, ciphertext_len);
        crypto_auth_hmacsha256_update(&state, tag, BACKUP_TAG_LEN);
        crypto_auth_hmacsha256_final(&state, hmac);

        size_t out_len = sizeof(header) + ciphertext_len + BACKUP_TAG_LEN + BACKUP_HMAC_LEN;
        auto* out = new unsigned char[out_len];
        std::memcpy(out, &header, sizeof(header));
        std::memcpy(out + sizeof(header), ciphertext, ciphertext_len);
        std::memcpy(out + sizeof(header) + ciphertext_len, tag, BACKUP_TAG_LEN);
        std::memcpy(out + sizeof(header) + ciphertext_len + BACKUP_TAG_LEN, hmac, BACKUP_HMAC_LEN);

        ok = write_file(dst_path, out, out_len);

        delete[] ciphertext;
        delete[] out;
    } while (false);

    secure_erase(db_data, db_len);
    delete[] db_data;
    return ok;
}

bool backup_restore(const char* src_path, const char* dst_path, const unsigned char* key,
                    size_t key_len) {
    if (!src_path || !dst_path || !key || key_len != 32)
        return false;

    unsigned char enc_key[32];
    unsigned char auth_key[32];
    derive_backup_keys(key, key_len, enc_key, auth_key);

    unsigned char* backup_data = nullptr;
    size_t backup_len = 0;
    if (!read_file(src_path, &backup_data, &backup_len))
        return false;

    bool ok = false;
    do {
        // Minimum size: header + tag + hmac
        if (backup_len < BACKUP_HEADER_LEN + BACKUP_TAG_LEN + BACKUP_HMAC_LEN)
            break;

        backup_header header;
        std::memcpy(&header, backup_data, BACKUP_HEADER_LEN);

        if (std::memcmp(header.magic, EXPECTED_MAGIC, BACKUP_MAGIC_LEN) != 0)
            break;

        if (header.version != BACKUP_VERSION)
            break;

        size_t ciphertext_len = backup_len - BACKUP_HEADER_LEN - BACKUP_TAG_LEN - BACKUP_HMAC_LEN;
        const unsigned char* ciphertext = backup_data + BACKUP_HEADER_LEN;
        const unsigned char* tag = ciphertext + ciphertext_len;
        const unsigned char* hmac_stored = tag + BACKUP_TAG_LEN;

        // Verify HMAC
        unsigned char hmac_computed[BACKUP_HMAC_LEN];
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, auth_key, sizeof(auth_key));
        crypto_auth_hmacsha256_update(&state, backup_data, BACKUP_HEADER_LEN);
        crypto_auth_hmacsha256_update(&state, ciphertext, ciphertext_len);
        crypto_auth_hmacsha256_update(&state, tag, BACKUP_TAG_LEN);
        crypto_auth_hmacsha256_final(&state, hmac_computed);

        if (sodium_memcmp(hmac_computed, hmac_stored, BACKUP_HMAC_LEN) != 0)
            break;

        // Decrypt
        auto* plaintext = new unsigned char[ciphertext_len];
        bool dec_ok =
            aes_gcm_decrypt(ciphertext, ciphertext_len, enc_key, sizeof(enc_key),
                            header.nonce, BACKUP_NONCE_LEN,
                            reinterpret_cast<const unsigned char*>(&header), sizeof(header), tag,
                            BACKUP_TAG_LEN, plaintext);

        if (!dec_ok) {
            delete[] plaintext;
            break;
        }

        ok = write_file(dst_path, plaintext, ciphertext_len);

        secure_erase(plaintext, ciphertext_len);
        delete[] plaintext;
    } while (false);

    secure_erase(backup_data, backup_len);
    delete[] backup_data;
    return ok;
}

}  // namespace ssm::v1

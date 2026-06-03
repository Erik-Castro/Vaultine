#include "backup/backup.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <ctime>

#include "crypto/aes_gcm.h"
#include "crypto/random.h"

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

bool backup_create(const char* src_path, const char* dst_path, const unsigned char* key,
                   size_t key_len) {
    if (!src_path || !dst_path || !key || key_len != 32)
        return false;

    unsigned char* db_data = nullptr;
    size_t db_len = 0;
    if (!read_file(src_path, &db_data, &db_len))
        return false;

    bool ok = false;
    do {
        backup_header header;
        std::memcpy(header.magic, EXPECTED_MAGIC, BACKUP_MAGIC_LEN);
        header.version = BACKUP_VERSION;
        header.timestamp = static_cast<uint32_t>(std::time(nullptr));
        random_bytes(header.nonce, BACKUP_NONCE_LEN);
        std::memset(header.reserved, 0, sizeof(header.reserved));

        size_t ciphertext_len = db_len;
        auto* ciphertext = new unsigned char[ciphertext_len];
        unsigned char tag[BACKUP_TAG_LEN];

        bool enc_ok = aes_gcm_encrypt(db_data, db_len, key, key_len, header.nonce, BACKUP_NONCE_LEN,
                                      reinterpret_cast<const unsigned char*>(&header),
                                      sizeof(header), ciphertext, tag, BACKUP_TAG_LEN);

        if (!enc_ok) {
            delete[] ciphertext;
            break;
        }

        size_t hmac_data_len = sizeof(header) + ciphertext_len + BACKUP_TAG_LEN;
        auto* hmac_data = new unsigned char[hmac_data_len];
        std::memcpy(hmac_data, &header, sizeof(header));
        std::memcpy(hmac_data + sizeof(header), ciphertext, ciphertext_len);
        std::memcpy(hmac_data + sizeof(header) + ciphertext_len, tag, BACKUP_TAG_LEN);

        unsigned char hmac[BACKUP_HMAC_LEN];
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, key, key_len);
        crypto_auth_hmacsha256_update(&state, hmac_data, hmac_data_len);
        crypto_auth_hmacsha256_final(&state, hmac);

        size_t out_len = sizeof(header) + ciphertext_len + BACKUP_TAG_LEN + BACKUP_HMAC_LEN;
        auto* out = new unsigned char[out_len];
        std::memcpy(out, &header, sizeof(header));
        std::memcpy(out + sizeof(header), ciphertext, ciphertext_len);
        std::memcpy(out + sizeof(header) + ciphertext_len, tag, BACKUP_TAG_LEN);
        std::memcpy(out + sizeof(header) + ciphertext_len + BACKUP_TAG_LEN, hmac, BACKUP_HMAC_LEN);

        ok = write_file(dst_path, out, out_len);

        delete[] ciphertext;
        delete[] hmac_data;
        delete[] out;
    } while (false);

    std::memset(db_data, 0, db_len);
    delete[] db_data;
    return ok;
}

bool backup_restore(const char* src_path, const char* dst_path, const unsigned char* key,
                    size_t key_len) {
    if (!src_path || !dst_path || !key || key_len != 32)
        return false;

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
        size_t hmac_data_len = BACKUP_HEADER_LEN + ciphertext_len + BACKUP_TAG_LEN;
        auto* hmac_data = new unsigned char[hmac_data_len];
        std::memcpy(hmac_data, backup_data, hmac_data_len);

        unsigned char hmac_computed[BACKUP_HMAC_LEN];
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, key, key_len);
        crypto_auth_hmacsha256_update(&state, hmac_data, hmac_data_len);
        crypto_auth_hmacsha256_final(&state, hmac_computed);

        if (sodium_memcmp(hmac_computed, hmac_stored, BACKUP_HMAC_LEN) != 0) {
            delete[] hmac_data;
            break;
        }
        delete[] hmac_data;

        // Decrypt
        auto* plaintext = new unsigned char[ciphertext_len];
        bool dec_ok =
            aes_gcm_decrypt(ciphertext, ciphertext_len, key, key_len, header.nonce,
                            BACKUP_NONCE_LEN, reinterpret_cast<const unsigned char*>(&header),
                            sizeof(header), tag, BACKUP_TAG_LEN, plaintext);

        if (!dec_ok) {
            delete[] plaintext;
            break;
        }

        ok = write_file(dst_path, plaintext, ciphertext_len);

        std::memset(plaintext, 0, ciphertext_len);
        delete[] plaintext;
    } while (false);

    std::memset(backup_data, 0, backup_len);
    delete[] backup_data;
    return ok;
}

}  // namespace ssm::v1

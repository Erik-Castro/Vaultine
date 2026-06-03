#pragma once

#include <cstddef>
#include <cstdint>

namespace ssm::v1 {

static constexpr size_t BACKUP_MAGIC_LEN = 8;
static constexpr size_t BACKUP_HEADER_LEN = 32;
static constexpr size_t BACKUP_NONCE_LEN = 12;
static constexpr size_t BACKUP_TAG_LEN = 16;
static constexpr size_t BACKUP_HMAC_LEN = 32;
static constexpr uint16_t BACKUP_VERSION = 1;

#pragma pack(push, 1)
struct backup_header {
    char magic[BACKUP_MAGIC_LEN];
    uint16_t version;
    uint32_t timestamp;
    unsigned char nonce[BACKUP_NONCE_LEN];
    unsigned char reserved[6];
};
#pragma pack(pop)

static_assert(sizeof(backup_header) == BACKUP_HEADER_LEN, "backup_header must be 32 bytes");

bool backup_create(const char* src_path, const char* dst_path, const unsigned char* key,
                   size_t key_len);

bool backup_restore(const char* src_path, const char* dst_path, const unsigned char* key,
                    size_t key_len);

}  // namespace ssm::v1

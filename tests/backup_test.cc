#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>

#include "backup/backup.h"
#include "ssm/ssm.h"

namespace ssm::v1 {
namespace {

const char* TEST_DB_PATH = ".ssm_backup_test.db";
const char* BACKUP_PATH = ".ssm_backup_test.bkp";
const char* RESTORE_PATH = ".ssm_backup_test_restored.db";
const unsigned char TEST_KEY[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
};

class BackupTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::remove(TEST_DB_PATH);
        std::remove(BACKUP_PATH);
        std::remove(RESTORE_PATH);

        ssm_handle* h = nullptr;
        ASSERT_EQ(ssm_init(&h, TEST_DB_PATH, nullptr, 0), SSM_OK);

        ASSERT_EQ(ssm_user_register(h, "alice", "test1234"), SSM_OK);

        unsigned char key[4] = {0xde, 0xad, 0xbe, 0xef};
        ASSERT_EQ(ssm_secret_store(h, "alice", key, sizeof(key), nullptr, 0,
                                   "my-key", "test secret"), SSM_OK);
        ssm_destroy(h);
    }

    void TearDown() override {
        std::remove(TEST_DB_PATH);
        std::remove(BACKUP_PATH);
        std::remove(RESTORE_PATH);
    }
};

TEST_F(BackupTest, CreateBackupSuccess) {
    ASSERT_TRUE(backup_create(TEST_DB_PATH, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)));

    FILE* f = std::fopen(BACKUP_PATH, "rb");
    ASSERT_NE(f, nullptr);

    backup_header header;
    ASSERT_EQ(std::fread(&header, 1, sizeof(header), f), sizeof(header));
    EXPECT_EQ(std::memcmp(header.magic, "VAULTBKP", 8), 0);
    EXPECT_EQ(header.version, 1);

    std::fseek(f, 0, SEEK_END);
    long file_size = std::ftell(f);
    std::fclose(f);

    EXPECT_GT(file_size, static_cast<long>(sizeof(backup_header) + BACKUP_TAG_LEN + BACKUP_HMAC_LEN));
}

TEST_F(BackupTest, CreateAndRestore) {
    ASSERT_TRUE(backup_create(TEST_DB_PATH, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)));
    ASSERT_TRUE(backup_restore(BACKUP_PATH, RESTORE_PATH, TEST_KEY, sizeof(TEST_KEY)));

    ssm_handle* h = nullptr;
    ASSERT_EQ(ssm_init(&h, RESTORE_PATH, nullptr, 0), SSM_OK);

    int valid = 0;
    ASSERT_EQ(ssm_user_authenticate(h, "alice", "test1234", &valid), SSM_OK);
    EXPECT_TRUE(valid);

    unsigned char out[16];
    size_t out_len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(h, "alice", "my-key", out, &out_len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(out_len, 4);
    EXPECT_EQ(std::memcmp(out, "\xde\xad\xbe\xef", 4), 0);

    ssm_destroy(h);
}

TEST_F(BackupTest, WrongKeyFailsDecrypt) {
    ASSERT_TRUE(backup_create(TEST_DB_PATH, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)));

    unsigned char wrong_key[32];
    std::memset(wrong_key, 0xff, sizeof(wrong_key));

    EXPECT_FALSE(backup_restore(BACKUP_PATH, RESTORE_PATH, wrong_key, sizeof(wrong_key)));
}

TEST_F(BackupTest, CorruptedFileFailsRestore) {
    ASSERT_TRUE(backup_create(TEST_DB_PATH, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)));

    FILE* f = std::fopen(BACKUP_PATH, "r+b");
    ASSERT_NE(f, nullptr);
    long pos = sizeof(backup_header) + 10;
    std::fseek(f, pos, SEEK_SET);
    unsigned char corrupt = 0xff;
    std::fwrite(&corrupt, 1, 1, f);
    std::fclose(f);

    EXPECT_FALSE(backup_restore(BACKUP_PATH, RESTORE_PATH, TEST_KEY, sizeof(TEST_KEY)));
}

TEST_F(BackupTest, CorruptedMagicFailsRestore) {
    ASSERT_TRUE(backup_create(TEST_DB_PATH, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)));

    FILE* f = std::fopen(BACKUP_PATH, "r+b");
    ASSERT_NE(f, nullptr);
    unsigned char bad_magic = 'X';
    std::fwrite(&bad_magic, 1, 1, f);
    std::fclose(f);

    EXPECT_FALSE(backup_restore(BACKUP_PATH, RESTORE_PATH, TEST_KEY, sizeof(TEST_KEY)));
}

TEST_F(BackupTest, ShortFileFailsRestore) {
    FILE* f = std::fopen(BACKUP_PATH, "wb");
    ASSERT_NE(f, nullptr);
    unsigned char junk[16] = {};
    std::fwrite(junk, sizeof(junk), 1, f);
    std::fclose(f);

    EXPECT_FALSE(backup_restore(BACKUP_PATH, RESTORE_PATH, TEST_KEY, sizeof(TEST_KEY)));
}

TEST_F(BackupTest, NullParamsFail) {
    EXPECT_FALSE(backup_create(nullptr, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)));
    EXPECT_FALSE(backup_create(TEST_DB_PATH, nullptr, TEST_KEY, sizeof(TEST_KEY)));
    EXPECT_FALSE(backup_create(TEST_DB_PATH, BACKUP_PATH, nullptr, sizeof(TEST_KEY)));
    EXPECT_FALSE(backup_create(TEST_DB_PATH, BACKUP_PATH, TEST_KEY, 16));  // wrong key size
    EXPECT_FALSE(backup_restore(nullptr, RESTORE_PATH, TEST_KEY, sizeof(TEST_KEY)));
    EXPECT_FALSE(backup_restore(BACKUP_PATH, nullptr, TEST_KEY, sizeof(TEST_KEY)));
    EXPECT_FALSE(backup_restore(BACKUP_PATH, RESTORE_PATH, nullptr, sizeof(TEST_KEY)));
}

TEST_F(BackupTest, SsmApiCreateRestore) {
    ssm_handle* h = nullptr;
    ASSERT_EQ(ssm_init(&h, TEST_DB_PATH, nullptr, 0), SSM_OK);

    ASSERT_EQ(ssm_backup_create(h, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)), SSM_OK);
    ssm_destroy(h);

    h = nullptr;
    ASSERT_EQ(ssm_init(&h, TEST_DB_PATH, nullptr, 0), SSM_OK);
    ASSERT_EQ(ssm_backup_restore(h, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)), SSM_OK);
    ssm_destroy(h);

    h = nullptr;
    ASSERT_EQ(ssm_init(&h, TEST_DB_PATH, nullptr, 0), SSM_OK);

    int valid = 0;
    ASSERT_EQ(ssm_user_authenticate(h, "alice", "test1234", &valid), SSM_OK);
    EXPECT_TRUE(valid);

    unsigned char out[16];
    size_t out_len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(h, "alice", "my-key", out, &out_len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(out_len, 4);

    ssm_destroy(h);
}

TEST_F(BackupTest, SsmApiNullHandle) {
    EXPECT_EQ(ssm_backup_create(nullptr, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)),
              SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_backup_restore(nullptr, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)),
              SSM_ERR_INTERNAL);
}

TEST_F(BackupTest, SsmApiBadKeyFails) {
    ssm_handle* h = nullptr;
    ASSERT_EQ(ssm_init(&h, TEST_DB_PATH, nullptr, 0), SSM_OK);

    unsigned char bad_key[32];
    std::memset(bad_key, 0, sizeof(bad_key));
    ASSERT_EQ(ssm_backup_create(h, BACKUP_PATH, bad_key, sizeof(bad_key)), SSM_OK);
    ssm_destroy(h);

    unsigned char wrong_key[32];
    std::memset(wrong_key, 0xff, sizeof(wrong_key));

    h = nullptr;
    ASSERT_EQ(ssm_init(&h, TEST_DB_PATH, nullptr, 0), SSM_OK);
    EXPECT_EQ(ssm_backup_restore(h, BACKUP_PATH, wrong_key, sizeof(wrong_key)),
              SSM_ERR_INTERNAL);
    ssm_destroy(h);
}

TEST_F(BackupTest, NullBackupKeyParamFails) {
    ssm_handle* h = nullptr;
    ASSERT_EQ(ssm_init(&h, TEST_DB_PATH, nullptr, 0), SSM_OK);
    EXPECT_EQ(ssm_backup_create(h, BACKUP_PATH, nullptr, 0), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_backup_restore(h, BACKUP_PATH, nullptr, 0), SSM_ERR_INTERNAL);
    ssm_destroy(h);
}

TEST_F(BackupTest, WALCheckpointBeforeBackup) {
    ssm_handle* h = nullptr;
    ASSERT_EQ(ssm_init(&h, TEST_DB_PATH, nullptr, 0), SSM_OK);

    unsigned char key[4] = {0x01, 0x02, 0x03, 0x04};
    ASSERT_EQ(ssm_secret_store(h, "alice", key, sizeof(key), nullptr, 0,
                               "wal-key", "after WAL"), SSM_OK);

    ASSERT_EQ(ssm_backup_create(h, BACKUP_PATH, TEST_KEY, sizeof(TEST_KEY)), SSM_OK);
    ssm_destroy(h);

    ASSERT_TRUE(backup_restore(BACKUP_PATH, RESTORE_PATH, TEST_KEY, sizeof(TEST_KEY)));

    h = nullptr;
    ASSERT_EQ(ssm_init(&h, RESTORE_PATH, nullptr, 0), SSM_OK);

    unsigned char out[16];
    size_t out_len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(h, "alice", "wal-key", out, &out_len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(out_len, 4);

    ssm_destroy(h);
}

}  // namespace
}  // namespace ssm::v1

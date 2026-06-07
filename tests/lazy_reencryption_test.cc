#include "ssm/ssm.h"

#include <gtest/gtest.h>
#include <sqlcipher.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "db/database.h"
#include "db/kek_archive.h"
#include "db/kek_metadata.h"
#include "db/secrets.h"
#include "db/users.h"
#include "utils/secure_memory.h"

namespace ssm::v1 {
namespace {

// ============================================================================
// Task 2.2 — Lazy-migrate in ssm_secret_get
// ============================================================================

class LazyReencryptionTest : public ::testing::Test {
protected:
    ssm_handle* handle_ = nullptr;
    const char* path_ = "/data/data/com.termux/files/usr/tmp/opencode/lazy_reencrypt.db";

    void SetUp() override {
        ::remove(path_);
        ASSERT_EQ(ssm_init(&handle_, path_, nullptr, 0), SSM_OK);
        ASSERT_NE(handle_, nullptr);
    }

    void TearDown() override {
        if (handle_) {
            ssm_destroy(handle_);
            handle_ = nullptr;
        }
        ::remove(path_);
    }

    // Helper: open a raw DB connection for verification
    sqlite3* open_raw() {
        sqlite3* db = nullptr;
        EXPECT_TRUE(db_open(path_, nullptr, 0, &db));
        return db;
    }

    // Helper: read kek_version directly from secrets table
    int64_t secret_kek_version(const char* username, const char* secret_name) {
        sqlite3* db = open_raw();
        if (!db) return -1;
        const char* sql =
            "SELECT s.kek_version FROM secrets s "
            "JOIN users u ON u.id = s.user_id "
            "WHERE u.username = ? AND s.name = ?";
        sqlite3_stmt* stmt = nullptr;
        int64_t ver = -1;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, secret_name, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW)
                ver = sqlite3_column_int64(stmt, 0);
            sqlite3_finalize(stmt);
        }
        db_close(db);
        return ver;
    }

    // Helper: check archive entry exists
    bool archive_exists(const char* username, int64_t kek_version) {
        sqlite3* db = open_raw();
        if (!db) return false;
        const char* sql =
            "SELECT COUNT(*) FROM kek_archive a "
            "JOIN users u ON u.id = a.user_id "
            "WHERE u.username = ? AND a.kek_version = ?";
        sqlite3_stmt* stmt = nullptr;
        bool exists = false;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 2, kek_version);
            if (sqlite3_step(stmt) == SQLITE_ROW)
                exists = sqlite3_column_int64(stmt, 0) > 0;
            sqlite3_finalize(stmt);
        }
        db_close(db);
        return exists;
    }

    // Helper: count archive entries for user
    int64_t archive_count(const char* username) {
        sqlite3* db = open_raw();
        if (!db) return -1;
        const char* sql =
            "SELECT COUNT(*) FROM kek_archive a "
            "JOIN users u ON u.id = a.user_id "
            "WHERE u.username = ?";
        sqlite3_stmt* stmt = nullptr;
        int64_t cnt = -1;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW)
                cnt = sqlite3_column_int64(stmt, 0);
            sqlite3_finalize(stmt);
        }
        db_close(db);
        return cnt;
    }
};

// 2.2 — Test: store with kek_version=1, rotate, get, verify kek_version updated
TEST_F(LazyReencryptionTest, LazyMigrateUpdatesKekVersionOnGet) {
    ASSERT_EQ(ssm_user_register(handle_, "lazy1", "password123"), SSM_OK);

    // Store secret at kek_version=1 (default)
    const unsigned char priv[] = "test-secret-32bytes-xxxxxxxxxxxxxx!!";
    ASSERT_EQ(ssm_secret_store(handle_, "lazy1", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Verify initial kek_version is 1
    EXPECT_EQ(secret_kek_version("lazy1", "mykey"), 1);

    // Rotate to kek_version=2 (archives version 1)
    ASSERT_EQ(ssm_kek_rotate(handle_, "lazy1"), SSM_OK);

    // Get secret — triggers lazy-migrate from version 1 to 2
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "lazy1", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(len, sizeof(priv));
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);

    // Verify kek_version was updated to 2
    EXPECT_EQ(secret_kek_version("lazy1", "mykey"), 2);
}

// 2.2 — Test: fast path — secret already has current kek_version
TEST_F(LazyReencryptionTest, LazyMigrateFastPathWhenCurrentVersion) {
    ASSERT_EQ(ssm_user_register(handle_, "fast1", "password123"), SSM_OK);

    const unsigned char priv[] = "fast-path-secret-data-32bytes!!!";
    ASSERT_EQ(ssm_secret_store(handle_, "fast1", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Get secret — both are at version 1, no archive needed
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "fast1", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(len, sizeof(priv));
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);

    // kek_version should remain 1
    EXPECT_EQ(secret_kek_version("fast1", "mykey"), 1);
}

// 2.2 — Test: secret with stale kek_version but missing archive → SSM_ERR_INTEGRITY
TEST_F(LazyReencryptionTest, LazyMigrateWithMissingArchiveReturnsIntegrityError) {
    ASSERT_EQ(ssm_user_register(handle_, "missing1", "password123"), SSM_OK);

    const unsigned char priv[] = "missing-archive-secret-key!!!";
    ASSERT_EQ(ssm_secret_store(handle_, "missing1", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Rotate (archives version 1)
    ASSERT_EQ(ssm_kek_rotate(handle_, "missing1"), SSM_OK);

    // Manually DELETE the archive entry to simulate corruption
    sqlite3* raw = open_raw();
    ASSERT_NE(raw, nullptr);
    sqlite3_exec(raw,
                 "DELETE FROM kek_archive "
                 "WHERE user_id = (SELECT id FROM users WHERE username = 'missing1')",
                 nullptr, nullptr, nullptr);
    db_close(raw);

    // Get secret — archive for version 1 is missing, should fail with INTEGRITY
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "missing1", "mykey", out, &len, nullptr, nullptr),
              SSM_ERR_INTEGRITY);
}

// ============================================================================
// Task 2.3 — Safe-purge after migrate
// ============================================================================

// 2.3 — Test: rotate, get secret (triggers migrate), verify old archive entry is deleted
TEST_F(LazyReencryptionTest, SafePurgeDeletesArchiveWhenLastSecretMigrates) {
    ASSERT_EQ(ssm_user_register(handle_, "purge1", "password123"), SSM_OK);

    // Store ONE secret
    const unsigned char priv[] = "only-one-secret-data-32bytes!!!";
    ASSERT_EQ(ssm_secret_store(handle_, "purge1", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Rotate to version 2
    ASSERT_EQ(ssm_kek_rotate(handle_, "purge1"), SSM_OK);

    // Verify archive entry exists
    EXPECT_TRUE(archive_exists("purge1", 1));

    // Get secret — migrates to version 2, should purge archive for version 1
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "purge1", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);

    // Archive entry for version 1 should be DELETED (count=0 after migrate)
    EXPECT_FALSE(archive_exists("purge1", 1));
}

// 2.3 — Test: if TWO secrets reference old version, archive persists after first migrate
TEST_F(LazyReencryptionTest, SafePurgePreservesArchiveWhenSecretsRemain) {
    ASSERT_EQ(ssm_user_register(handle_, "purge2", "password123"), SSM_OK);

    const unsigned char priv[] = "shared-version-key-data-32bytes!!";
    ASSERT_EQ(ssm_secret_store(handle_, "purge2", priv, sizeof(priv), nullptr, 0, "key1", nullptr),
              SSM_OK);
    ASSERT_EQ(ssm_secret_store(handle_, "purge2", priv, sizeof(priv), nullptr, 0, "key2", nullptr),
              SSM_OK);

    // Rotate to version 2
    ASSERT_EQ(ssm_kek_rotate(handle_, "purge2"), SSM_OK);

    // Get key1 — migrates to version 2, but key2 still at version 1
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "purge2", "key1", out, &len, nullptr, nullptr), SSM_OK);

    // Archive should still exist (one secret still at version 1)
    EXPECT_TRUE(archive_exists("purge2", 1));

    // Get key2 — migrates the last secret
    ASSERT_EQ(ssm_secret_get(handle_, "purge2", "key2", out, &len, nullptr, nullptr), SSM_OK);

    // Now archive should be deleted (no secrets left at version 1)
    EXPECT_FALSE(archive_exists("purge2", 1));
}

// 2.3 — Test: archive persists with >0 count even after some migrate
TEST_F(LazyReencryptionTest, SafePurgeCountRespected) {
    ASSERT_EQ(ssm_user_register(handle_, "purge3", "password123"), SSM_OK);

    const unsigned char priv[] = "count-respected-data-32bytes!!!!";
    ASSERT_EQ(ssm_secret_store(handle_, "purge3", priv, sizeof(priv), nullptr, 0, "ka", nullptr),
              SSM_OK);
    ASSERT_EQ(ssm_secret_store(handle_, "purge3", priv, sizeof(priv), nullptr, 0, "kb", nullptr),
              SSM_OK);
    ASSERT_EQ(ssm_secret_store(handle_, "purge3", priv, sizeof(priv), nullptr, 0, "kc", nullptr),
              SSM_OK);

    // Rotate to version 2
    ASSERT_EQ(ssm_kek_rotate(handle_, "purge3"), SSM_OK);

    // Migrate only ONE of three secrets
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "purge3", "ka", out, &len, nullptr, nullptr), SSM_OK);

    // Archive must persist — 2 secrets still at version 1
    EXPECT_TRUE(archive_exists("purge3", 1));
    EXPECT_EQ(archive_count("purge3"), 1);
}

// ============================================================================
// Task 2.4 — ssm_kek_purge_archive
// ============================================================================

// 2.4 — Test: purge with no archive entries → no error
TEST_F(LazyReencryptionTest, PurgeArchiveWithNoEntries) {
    ASSERT_EQ(ssm_user_register(handle_, "nopurge", "password123"), SSM_OK);

    // No archive entries exist (no rotations done)
    EXPECT_EQ(ssm_kek_purge_archive(handle_, "nopurge"), SSM_OK);
}

// 2.4 — Test: purge when all secrets migrated → deletes archive entries
TEST_F(LazyReencryptionTest, PurgeArchiveWhenAllMigrated) {
    ASSERT_EQ(ssm_user_register(handle_, "purgeall", "password123"), SSM_OK);

    const unsigned char priv[] = "purge-all-secrets-data-32bytes!!";
    ASSERT_EQ(ssm_secret_store(handle_, "purgeall", priv, sizeof(priv), nullptr, 0, "k1", nullptr),
              SSM_OK);

    // Rotate twice — creates 2 archive entries
    ASSERT_EQ(ssm_kek_rotate(handle_, "purgeall"), SSM_OK);
    ASSERT_EQ(ssm_kek_rotate(handle_, "purgeall"), SSM_OK);

    // Verify 2 archive entries
    EXPECT_EQ(archive_count("purgeall"), 2);

    // Migrate the secret through both versions (via 2 gets) — assumes migration handles
    // version gaps: version 1→3 via sequential gets
    // Actually: secret is at version 1 after first get it goes to 2, archive v1 stays
    // Second get: secret at 2, current at 3, migrates 2→3, archive v2 stays
    // Then purge should delete both archives since no secrets reference them
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "purgeall", "k1", out, &len, nullptr, nullptr), SSM_OK);
    ASSERT_EQ(ssm_secret_get(handle_, "purgeall", "k1", out, &len, nullptr, nullptr), SSM_OK);

    // Now purge
    EXPECT_EQ(ssm_kek_purge_archive(handle_, "purgeall"), SSM_OK);

    // All archive entries should be deleted
    EXPECT_EQ(archive_count("purgeall"), 0);
}

// 2.4 — Test: purge when secrets still reference old version → archives preserved
TEST_F(LazyReencryptionTest, PurgeArchivePreservesWhenSecretsRemain) {
    ASSERT_EQ(ssm_user_register(handle_, "preserve", "password123"), SSM_OK);

    const unsigned char priv[] = "preserved-data-32bytes-xxxxxxxxx!!";
    ASSERT_EQ(ssm_secret_store(handle_, "preserve", priv, sizeof(priv), nullptr, 0, "k1", nullptr),
              SSM_OK);
    ASSERT_EQ(ssm_secret_store(handle_, "preserve", priv, sizeof(priv), nullptr, 0, "k2", nullptr),
              SSM_OK);

    // Rotate once — creates archive entry for version 1
    ASSERT_EQ(ssm_kek_rotate(handle_, "preserve"), SSM_OK);

    // Migrate only one secret
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "preserve", "k1", out, &len, nullptr, nullptr), SSM_OK);

    // One secret still at version 1 — purge should preserve archive
    EXPECT_EQ(ssm_kek_purge_archive(handle_, "preserve"), SSM_OK);

    // Archive should still exist (one secret at version 1)
    EXPECT_TRUE(archive_exists("preserve", 1));
}

// ============================================================================
// Task 3.1 — Password change with 3 archived KEKs
// ============================================================================

TEST_F(LazyReencryptionTest, PasswordChangeWithThreeArchiveEntries) {
    ASSERT_EQ(ssm_user_register(handle_, "pwarch", "oldpassword123"), SSM_OK);

    // Store a secret
    const unsigned char priv[] = "password-change-archive-data-32b!";
    ASSERT_EQ(ssm_secret_store(handle_, "pwarch", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Rotate 3 times (creates 3 archive entries: versions 1, 2, 3; current = 4)
    ASSERT_EQ(ssm_kek_rotate(handle_, "pwarch"), SSM_OK);
    ASSERT_EQ(ssm_kek_rotate(handle_, "pwarch"), SSM_OK);
    ASSERT_EQ(ssm_kek_rotate(handle_, "pwarch"), SSM_OK);

    // Verify 3 archive entries
    EXPECT_EQ(archive_count("pwarch"), 3);

    // Change password — must re-wrap all 3 archives + current KEK
    ASSERT_EQ(ssm_user_change_password(handle_, "pwarch", "oldpassword123", "newpassword456"),
              SSM_OK);

    // Verify new password works
    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(handle_, "pwarch", "newpassword456", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);

    // Old password should fail
    EXPECT_EQ(ssm_user_authenticate(handle_, "pwarch", "oldpassword123", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);

    // Get secret — should still decrypt correctly (archive re-wrap worked)
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "pwarch", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);

    // Archive entries should still exist (3 entries, all re-wrapped)
    EXPECT_EQ(archive_count("pwarch"), 3);
}

// ============================================================================
// Task 3.2 — Password change with 0 archive entries
// ============================================================================

TEST_F(LazyReencryptionTest, PasswordChangeWithNoArchiveEntries) {
    ASSERT_EQ(ssm_user_register(handle_, "noarch", "oldpassword123"), SSM_OK);

    // Store a secret (no rotations yet)
    const unsigned char priv[] = "no-archive-change-data-32bytes!!";
    ASSERT_EQ(ssm_secret_store(handle_, "noarch", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Verify no archive entries
    EXPECT_EQ(archive_count("noarch"), 0);

    // Change password — no archive to re-wrap, should succeed
    ASSERT_EQ(ssm_user_change_password(handle_, "noarch", "oldpassword123", "newpassword456"),
              SSM_OK);

    // Verify new password works
    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(handle_, "noarch", "newpassword456", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);

    // Verify secret still accessible
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "noarch", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);
}

// ============================================================================
// Task 4.1 — Integration: full cycle
// ============================================================================

TEST_F(LazyReencryptionTest, FullCycleRegisterRotateStoreMigratePurge) {
    ASSERT_EQ(ssm_user_register(handle_, "fullcyc", "password123"), SSM_OK);

    // Rotate (O(1), no secrets) — archive version 1, new version 2
    ASSERT_EQ(ssm_kek_rotate(handle_, "fullcyc"), SSM_OK);

    // Verify archive entry exists
    EXPECT_TRUE(archive_exists("fullcyc", 1));

    // Now store a secret (uses current KEK version 2)
    const unsigned char priv[] = "full-cycle-integration-test-data!";
    ASSERT_EQ(ssm_secret_store(handle_, "fullcyc", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Verify secret starts at kek_version 2
    EXPECT_EQ(secret_kek_version("fullcyc", "mykey"), 2);

    // Rotate again — archive version 2, new version 3
    ASSERT_EQ(ssm_kek_rotate(handle_, "fullcyc"), SSM_OK);

    // Verify archive entries for both 1 and 2
    EXPECT_TRUE(archive_exists("fullcyc", 1));
    EXPECT_TRUE(archive_exists("fullcyc", 2));

    // Get secret — should lazy-migrate from version 2 to 3
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "fullcyc", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);

    // Verify kek_version updated to 3
    EXPECT_EQ(secret_kek_version("fullcyc", "mykey"), 3);

    // Archive version 2 should be purged (no secrets at v2)
    // Archive version 1 should still exist (no secrets ever referenced it after store at v2)
    EXPECT_FALSE(archive_exists("fullcyc", 2));
    EXPECT_TRUE(archive_exists("fullcyc", 1));

    // Explicit purge should delete archive version 1
    EXPECT_EQ(ssm_kek_purge_archive(handle_, "fullcyc"), SSM_OK);
    EXPECT_FALSE(archive_exists("fullcyc", 1));
}

// ============================================================================
// Task 4.2 — Integration: password change + archive
// ============================================================================

TEST_F(LazyReencryptionTest, PasswordChangeThenLazyMigrate) {
    ASSERT_EQ(ssm_user_register(handle_, "pwlm", "originalpw"), SSM_OK);

    // Store secret
    const unsigned char priv[] = "pw-change-lazy-migrate-data-32!";
    ASSERT_EQ(ssm_secret_store(handle_, "pwlm", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Rotate twice (archive v1, v2; current v3)
    ASSERT_EQ(ssm_kek_rotate(handle_, "pwlm"), SSM_OK);
    ASSERT_EQ(ssm_kek_rotate(handle_, "pwlm"), SSM_OK);

    // Change password — re-wraps all 3 KEKs (current + 2 archives)
    ASSERT_EQ(ssm_user_change_password(handle_, "pwlm", "originalpw", "newpw456"), SSM_OK);

    // Login with new password
    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(handle_, "pwlm", "newpw456", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);

    // Get secret encrypted with oldest KEK (version 1) — lazy-migrate must work
    // Secret starts at v1, current is v3, needs 2-step migrate (v1→v3)
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "pwlm", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);

    // Verify secret now at version 3
    EXPECT_EQ(secret_kek_version("pwlm", "mykey"), 3);
}

// ============================================================================
// Task 4.3 — Concurrency: 10 threads on stale secrets
// ============================================================================

TEST_F(LazyReencryptionTest, ConcurrentStaleSecretMigrate) {
    ASSERT_EQ(ssm_user_register(handle_, "concurr", "password123"), SSM_OK);

    // Store 10 secrets at version 1
    const unsigned char priv[] = "concurrent-migrate-data-32bytes!";
    for (int i = 0; i < 10; ++i) {
        char name[16];
        std::snprintf(name, sizeof(name), "k%d", i);
        ASSERT_EQ(ssm_secret_store(handle_, "concurr", priv, sizeof(priv), nullptr, 0, name,
                                   nullptr), SSM_OK);
    }

    // Rotate to version 2 (all secrets now stale)
    ASSERT_EQ(ssm_kek_rotate(handle_, "concurr"), SSM_OK);

    // 10 threads each get a different stale secret simultaneously
    std::atomic<int> ok_count{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([this, i, &ok_count]() {
            char name[16];
            std::snprintf(name, sizeof(name), "k%d", i);
            unsigned char out[64] = {};
            size_t len = sizeof(out);
            if (ssm_secret_get(handle_, "concurr", name, out, &len, nullptr, nullptr) == SSM_OK)
                ++ok_count;
        });
    }
    for (auto& t : threads)
        t.join();

    EXPECT_EQ(ok_count.load(), 10);

    // All secrets should now be at kek_version 2
    for (int i = 0; i < 10; ++i) {
        char name[16];
        std::snprintf(name, sizeof(name), "k%d", i);
        EXPECT_EQ(secret_kek_version("concurr", name), 2);
    }

    // Archive for version 1 should be deleted (all 10 secrets migrated)
    EXPECT_FALSE(archive_exists("concurr", 1));
}

// ============================================================================
// Additional edge cases
// ============================================================================

TEST_F(LazyReencryptionTest, RotateTwiceThenMigrateTwice) {
    ASSERT_EQ(ssm_user_register(handle_, "rot2mig2", "password123"), SSM_OK);

    const unsigned char priv[] = "double-rotate-double-migrate-data";
    ASSERT_EQ(ssm_secret_store(handle_, "rot2mig2", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    // Rotate twice: versions go 1→2→3, archives for 1 and 2
    ASSERT_EQ(ssm_kek_rotate(handle_, "rot2mig2"), SSM_OK);
    ASSERT_EQ(ssm_kek_rotate(handle_, "rot2mig2"), SSM_OK);

    EXPECT_TRUE(archive_exists("rot2mig2", 1));
    EXPECT_TRUE(archive_exists("rot2mig2", 2));

    // First get: migrate 1→2 (archive v1 should NOT purge since secret now at 2, not current)
    // Actually with our one-step migration: 1→3 directly via archive lookup
    // The design says: compare secret's kek_version with current, if stale, look up archive for secret's version
    // So from v1→v3 directly using archive entry for v1
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "rot2mig2", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);

    // After first get: secret at v3, archive v1 purged (no secrets at v1)
    EXPECT_EQ(secret_kek_version("rot2mig2", "mykey"), 3);
    EXPECT_FALSE(archive_exists("rot2mig2", 1));
    // Archive v2 also purged? No — secret was never at v2. It went from 1→3 directly.
    // But v2 was never referenced by any secret so count was always 0
    // So ssm_kek_purge_archive would clean it, but inline purge only triggers for the old_version
    // Wait, the inline purge only happens for the OLD version (the one we migrated FROM)
    // So v1 gets purged. v2 is still there.
    // Hmm, actually v2's count was already 0 before the migrate (no secret was ever at v2)
    // But the inline purge only checks AND cleans the exact old_version
    // So v2 remains orphaned until explicit ssm_kek_purge_archive

    // Verify v2 archive still exists (not purged inline since no secret referenced it)
    // This is expected — explicit purge is needed for orphaned archives
    EXPECT_TRUE(archive_exists("rot2mig2", 2));

    // Explicit purge
    EXPECT_EQ(ssm_kek_purge_archive(handle_, "rot2mig2"), SSM_OK);
    EXPECT_FALSE(archive_exists("rot2mig2", 2));
}

}  // namespace
}  // namespace ssm::v1

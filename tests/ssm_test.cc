#include "ssm/ssm.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "db/database.h"

#include "utils/secure_memory.h"

#include <sqlcipher.h>

namespace ssm::v1 {
namespace {

class SsmApiTest : public ::testing::Test {
protected:
    ssm_handle* handle_ = nullptr;

    void SetUp() override {
        ASSERT_EQ(ssm_init(&handle_, ":memory:", nullptr, 0), SSM_OK);
        ASSERT_NE(handle_, nullptr);
    }

    void TearDown() override {
        if (handle_)
            ssm_destroy(handle_);
    }
};

TEST_F(SsmApiTest, RegisterAndAuthenticate) {
    EXPECT_EQ(ssm_user_register(handle_, "alice", "p@ssw0rd"), SSM_OK);

    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(handle_, "alice", "p@ssw0rd", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);
}

TEST_F(SsmApiTest, AuthenticateWrongPassword) {
    ASSERT_EQ(ssm_user_register(handle_, "bob", "secret"), SSM_OK);

    int valid = 1;
    EXPECT_EQ(ssm_user_authenticate(handle_, "bob", "wrong", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);
}

TEST_F(SsmApiTest, AuthenticateUnknownUser) {
    int valid = 1;
    EXPECT_EQ(ssm_user_authenticate(handle_, "nobody", "x", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);
}

TEST_F(SsmApiTest, DuplicateRegistrationFails) {
    ASSERT_EQ(ssm_user_register(handle_, "carol", "pass"), SSM_OK);
    EXPECT_EQ(ssm_user_register(handle_, "carol", "pass"), SSM_ERR_AUTH);
}

TEST_F(SsmApiTest, StoreAndGetSecret) {
    ASSERT_EQ(ssm_user_register(handle_, "dave", "p@ss"), SSM_OK);

    const unsigned char priv[] = "my-ecdsa-private-key-32bytes!!";
    EXPECT_EQ(
        ssm_secret_store(handle_, "dave", priv, sizeof(priv), nullptr, 0, "key1", "my first key"),
        SSM_OK);

    unsigned char priv_out[64] = {};
    size_t priv_len = sizeof(priv_out);
    EXPECT_EQ(ssm_secret_get(handle_, "dave", "key1", priv_out, &priv_len, nullptr, nullptr),
              SSM_OK);
    EXPECT_EQ(priv_len, sizeof(priv));
    EXPECT_EQ(std::memcmp(priv_out, priv, sizeof(priv)), 0);
}

TEST_F(SsmApiTest, StoreAndGetSecretWithPublicKey) {
    ASSERT_EQ(ssm_user_register(handle_, "eve", "s3cret"), SSM_OK);

    const unsigned char priv[] = "private-key-blob-here-32bytes!";
    const unsigned char pub[] = "public-key-blob-here-28bytes!";
    EXPECT_EQ(ssm_secret_store(handle_, "eve", priv, sizeof(priv), pub, sizeof(pub), "keypair",
                               "with pub"),
              SSM_OK);

    unsigned char priv_out[64] = {};
    size_t priv_len = sizeof(priv_out);
    unsigned char pub_out[64] = {};
    size_t pub_len = sizeof(pub_out);
    EXPECT_EQ(ssm_secret_get(handle_, "eve", "keypair", priv_out, &priv_len, pub_out, &pub_len),
              SSM_OK);
    EXPECT_EQ(priv_len, sizeof(priv));
    EXPECT_EQ(pub_len, sizeof(pub));
    EXPECT_EQ(std::memcmp(priv_out, priv, sizeof(priv)), 0);
    EXPECT_EQ(std::memcmp(pub_out, pub, sizeof(pub)), 0);
}

TEST_F(SsmApiTest, GetNonExistentSecret) {
    ASSERT_EQ(ssm_user_register(handle_, "frank", "pass1234"), SSM_OK);

    unsigned char out[8] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "frank", "nonexistent", out, &len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);
}

TEST_F(SsmApiTest, DeleteSecret) {
    ASSERT_EQ(ssm_user_register(handle_, "grace", "pass1234"), SSM_OK);

    const unsigned char priv[] = "delete-me-key";
    ASSERT_EQ(
        ssm_secret_store(handle_, "grace", priv, sizeof(priv), nullptr, 0, "temp", "will delete"),
        SSM_OK);

    EXPECT_EQ(ssm_secret_delete(handle_, "grace", "temp"), SSM_OK);

    unsigned char out[16] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "grace", "temp", out, &len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);
}

TEST_F(SsmApiTest, DeleteNonExistentSecret) {
    ASSERT_EQ(ssm_user_register(handle_, "hank", "pass1234"), SSM_OK);
    EXPECT_EQ(ssm_secret_delete(handle_, "hank", "ghost"), SSM_ERR_NOT_FOUND);
}

class SsmApiFileTest : public ::testing::Test {
protected:
    ssm_handle* handle_ = nullptr;
    const char* path_ = "/data/data/com.termux/files/usr/tmp/opencode/ssm_test_file.db";

    void SetUp() override {
        ::remove(path_);
        ASSERT_EQ(ssm_init(&handle_, path_, nullptr, 0), SSM_OK);
        ASSERT_NE(handle_, nullptr);
    }

    void TearDown() override {
        if (handle_)
            ssm_destroy(handle_);
        ::remove(path_);
    }
};

TEST_F(SsmApiFileTest, DeleteSecretWithExpiredKek) {
    ASSERT_EQ(ssm_user_register(handle_, "iris", "pass1234"), SSM_OK);

    const unsigned char priv[] = "expired-kek-test";
    ASSERT_EQ(
        ssm_secret_store(handle_, "iris", priv, sizeof(priv), nullptr, 0, "tmp", nullptr),
        SSM_OK);

    ssm_destroy(handle_);
    handle_ = nullptr;

    // second connection to force KEK expired
    sqlite3* raw_db = nullptr;
    ASSERT_TRUE(db_open(path_, nullptr, 0, &raw_db));
    char* err = nullptr;
    ASSERT_EQ(
        sqlite3_exec(raw_db,
            "UPDATE kek_metadata SET expires_at = '2020-01-01T00:00:00Z' "
            "WHERE user_id = (SELECT id FROM users WHERE username = 'iris')",
            nullptr, nullptr, &err),
        SQLITE_OK);
    sqlite3_free(err);
    db_close(raw_db);

    ASSERT_EQ(ssm_init(&handle_, path_, nullptr, 0), SSM_OK);
    EXPECT_EQ(ssm_secret_delete(handle_, "iris", "tmp"), SSM_ERR_EXPIRED);
}

TEST_F(SsmApiTest, RotateAndSecretsStillAccessible) {
    ASSERT_EQ(ssm_user_register(handle_, "ivy", "mypass"), SSM_OK);

    const unsigned char priv[] = "important-key-never-lose-32byte!";
    ASSERT_EQ(ssm_secret_store(handle_, "ivy", priv, sizeof(priv), nullptr, 0, "critical", "test"),
              SSM_OK);

    EXPECT_EQ(ssm_kek_rotate(handle_, "ivy"), SSM_OK);

    unsigned char priv_out[64] = {};
    size_t priv_len = sizeof(priv_out);
    EXPECT_EQ(ssm_secret_get(handle_, "ivy", "critical", priv_out, &priv_len, nullptr, nullptr),
              SSM_OK);
    EXPECT_EQ(priv_len, sizeof(priv));
    EXPECT_EQ(std::memcmp(priv_out, priv, sizeof(priv)), 0);
}

TEST_F(SsmApiTest, RotateMultipleSecrets) {
    ASSERT_EQ(ssm_user_register(handle_, "jack", "pass1234"), SSM_OK);

    for (int i = 0; i < 5; ++i) {
        unsigned char priv[16];
        std::memset(priv, 'A' + i, sizeof(priv));
        char name[8];
        std::snprintf(name, sizeof(name), "k%d", i);
        ASSERT_EQ(ssm_secret_store(handle_, "jack", priv, sizeof(priv), nullptr, 0, name, nullptr),
                  SSM_OK);
    }

    ASSERT_EQ(ssm_kek_rotate(handle_, "jack"), SSM_OK);

    for (int i = 0; i < 5; ++i) {
        unsigned char expected[16];
        std::memset(expected, 'A' + i, sizeof(expected));
        unsigned char out[16] = {};
        size_t out_len = sizeof(out);
        char name[8];
        std::snprintf(name, sizeof(name), "k%d", i);
        ASSERT_EQ(ssm_secret_get(handle_, "jack", name, out, &out_len, nullptr, nullptr), SSM_OK);
        EXPECT_EQ(out_len, sizeof(expected));
        EXPECT_EQ(std::memcmp(out, expected, sizeof(expected)), 0);
    }
}

TEST_F(SsmApiTest, UserIsolation) {
    ASSERT_EQ(ssm_user_register(handle_, "user1", "pass1"), SSM_OK);
    ASSERT_EQ(ssm_user_register(handle_, "user2", "pass2"), SSM_OK);

    const unsigned char priv[] = "user1-private-key-data-here!";
    ASSERT_EQ(ssm_secret_store(handle_, "user1", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    unsigned char out[64] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "user2", "mykey", out, &len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);
}

TEST_F(SsmApiTest, RotateNonExistentUser) {
    int valid = 0;
    ASSERT_EQ(ssm_user_authenticate(handle_, "ghost", "x", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);

    EXPECT_EQ(ssm_kek_rotate(handle_, "ghost"), SSM_ERR_AUTH);
}

TEST_F(SsmApiTest, DeleteUserAndSecretsGone) {
    ASSERT_EQ(ssm_user_register(handle_, "zara", "pass"), SSM_OK);

    const unsigned char priv[] = "will-be-deleted-with-user";
    ASSERT_EQ(ssm_secret_store(handle_, "zara", priv, sizeof(priv), nullptr, 0, "mykey", nullptr),
              SSM_OK);

    EXPECT_EQ(ssm_user_delete(handle_, "zara", "pass"), SSM_OK);

    // user should be gone — authenticate should fail
    int valid = 1;
    EXPECT_EQ(ssm_user_authenticate(handle_, "zara", "pass", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);
}

TEST_F(SsmApiTest, DeleteUserWrongPassword) {
    ASSERT_EQ(ssm_user_register(handle_, "yves", "correct"), SSM_OK);
    EXPECT_EQ(ssm_user_delete(handle_, "yves", "wrong"), SSM_ERR_AUTH);
}

TEST_F(SsmApiTest, DeleteNonExistentUser) {
    EXPECT_EQ(ssm_user_delete(handle_, "ghost", "x"), SSM_ERR_AUTH);
}

TEST_F(SsmApiTest, ChangePasswordAndAccessSecrets) {
    ASSERT_EQ(ssm_user_register(handle_, "victor", "oldpass"), SSM_OK);

    const unsigned char priv[] = "secret-after-pw-change!";
    ASSERT_EQ(ssm_secret_store(handle_, "victor", priv, sizeof(priv), nullptr, 0,
                               "mykey", nullptr), SSM_OK);

    EXPECT_EQ(ssm_user_change_password(handle_, "victor", "oldpass", "newpass"), SSM_OK);

    // old password should no longer work
    int valid = 1;
    EXPECT_EQ(ssm_user_authenticate(handle_, "victor", "oldpass", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);

    // new password should work
    EXPECT_EQ(ssm_user_authenticate(handle_, "victor", "newpass", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);

    // secrets still accessible with new password
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "victor", "mykey", out, &len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(len, sizeof(priv));
    EXPECT_EQ(std::memcmp(out, priv, sizeof(priv)), 0);
}

TEST_F(SsmApiTest, ChangePasswordWrongOldPassword) {
    ASSERT_EQ(ssm_user_register(handle_, "una", "realpw"), SSM_OK);
    EXPECT_EQ(ssm_user_change_password(handle_, "una", "wrong", "new!"), SSM_ERR_AUTH);

    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(handle_, "una", "realpw", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);
}

TEST_F(SsmApiTest, ChangePasswordEmptyPassword) {
    ASSERT_EQ(ssm_user_register(handle_, "trent", "pass1234"), SSM_OK);
    EXPECT_EQ(ssm_user_change_password(handle_, "trent", "pass1234", ""), SSM_ERR_INTERNAL);
}

namespace {
struct ListCollector {
    std::vector<std::string> names;
    std::vector<std::string> descriptions;
    std::vector<size_t> pub_key_lens;
};

void collect_names(const char* name, const char* desc, const char* updated_at,
                   size_t pub_key_len, void* user_data) {
    auto* c = static_cast<ListCollector*>(user_data);
    c->names.push_back(name ? name : "");
    c->descriptions.push_back(desc ? desc : "");
    c->pub_key_lens.push_back(pub_key_len);
    (void)updated_at;
}
}

TEST_F(SsmApiTest, ListSecrets) {
    ASSERT_EQ(ssm_user_register(handle_, "xavier", "pass1234"), SSM_OK);

    const unsigned char priv[] = "key-material-here-32bytes!";
    const unsigned char pub[] = "pub-key-here!";
    ASSERT_EQ(ssm_secret_store(handle_, "xavier", priv, sizeof(priv), pub, sizeof(pub),
                               "key1", "first key"), SSM_OK);
    ASSERT_EQ(ssm_secret_store(handle_, "xavier", priv, sizeof(priv), nullptr, 0,
                               "key2", "second key"), SSM_OK);

    ListCollector c;
    EXPECT_EQ(ssm_secret_list(handle_, "xavier", collect_names, &c), SSM_OK);
    EXPECT_EQ(c.names.size(), 2);
    EXPECT_EQ(c.descriptions.size(), 2);
    EXPECT_EQ(c.pub_key_lens.size(), 2);
    // both keys present
    EXPECT_NE(std::find(c.names.begin(), c.names.end(), "key1"), c.names.end());
    EXPECT_NE(std::find(c.names.begin(), c.names.end(), "key2"), c.names.end());
    // key1 has pub key, key2 doesn't
    // key1 is first stored — might be returned after key2 in the list
    auto idx1 = std::find(c.names.begin(), c.names.end(), "key1") - c.names.begin();
    EXPECT_EQ(c.pub_key_lens[idx1], sizeof(pub));
    auto idx2 = std::find(c.names.begin(), c.names.end(), "key2") - c.names.begin();
    EXPECT_EQ(c.pub_key_lens[idx2], 0);
}

TEST_F(SsmApiTest, ListSecretsWithExpiredKek) {
    ASSERT_EQ(ssm_user_register(handle_, "walter", "pass1234"), SSM_OK);
    const unsigned char priv[] = "some-key";
    ASSERT_EQ(ssm_secret_store(handle_, "walter", priv, sizeof(priv), nullptr, 0,
                                "k", nullptr), SSM_OK);

    // destroy and re-open to test with a file DB for expired KEK manipulation
    ssm_destroy(handle_);
    handle_ = nullptr;

    const char* path = "/data/data/com.termux/files/usr/tmp/opencode/ssm_list_expired.db";
    ::remove(path);
    ASSERT_EQ(ssm_init(&handle_, path, nullptr, 0), SSM_OK);
    ASSERT_EQ(ssm_user_register(handle_, "walter", "pass1234"), SSM_OK);
    ASSERT_EQ(ssm_secret_store(handle_, "walter", priv, sizeof(priv), nullptr, 0,
                               "k", nullptr), SSM_OK);
    ssm_destroy(handle_);
    handle_ = nullptr;

    sqlite3* raw = nullptr;
    ASSERT_TRUE(db_open(path, nullptr, 0, &raw));
    sqlite3_exec(raw,
        "UPDATE kek_metadata SET expires_at = '2020-01-01T00:00:00Z' "
        "WHERE user_id = (SELECT id FROM users WHERE username = 'walter')",
        nullptr, nullptr, nullptr);
    db_close(raw);

    ASSERT_EQ(ssm_init(&handle_, path, nullptr, 0), SSM_OK);
    ListCollector c;
    EXPECT_EQ(ssm_secret_list(handle_, "walter", collect_names, &c), SSM_ERR_EXPIRED);
    EXPECT_EQ(c.names.size(), 0);

    ssm_destroy(handle_);
    handle_ = nullptr;
    ::remove(path);
    ASSERT_EQ(ssm_init(&handle_, ":memory:", nullptr, 0), SSM_OK);
}

TEST_F(SsmApiTest, NullHandleReturnsError) {
    unsigned char buf[8] = {};
    size_t len = sizeof(buf);
    int valid = 0;

    EXPECT_EQ(ssm_init(nullptr, ":memory:", nullptr, 0), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_destroy(nullptr), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_user_register(nullptr, "a", "b"), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_user_authenticate(nullptr, "a", "b", &valid), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_secret_store(nullptr, "a", buf, len, nullptr, 0, "n", "d"), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_secret_get(nullptr, "a", "n", buf, &len, nullptr, nullptr), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_secret_delete(nullptr, "a", "n"), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_user_delete(nullptr, "a", "b"), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_user_change_password(nullptr, "a", "o", "n"), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_secret_list(nullptr, "a", nullptr, nullptr), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_kek_rotate(nullptr, "a"), SSM_ERR_INTERNAL);
}

TEST_F(SsmApiTest, StatusToString) {
    EXPECT_STREQ(ssm_status_to_string(SSM_OK), "SSM_OK");
    EXPECT_STREQ(ssm_status_to_string(SSM_ERR_AUTH), "SSM_ERR_AUTH");
    EXPECT_STREQ(ssm_status_to_string(SSM_ERR_NOT_FOUND), "SSM_ERR_NOT_FOUND");
    EXPECT_STREQ(ssm_status_to_string(SSM_ERR_EXPIRED), "SSM_ERR_EXPIRED");
    EXPECT_STREQ(ssm_status_to_string(SSM_ERR_INTEGRITY), "SSM_ERR_INTEGRITY");
    EXPECT_STREQ(ssm_status_to_string(SSM_ERR_INTERNAL), "SSM_ERR_INTERNAL");
    EXPECT_STREQ(ssm_status_to_string(static_cast<ssm_status>(99)), "SSM_ERR_UNKNOWN");
}

// ── Tag corruption (integrity validation) ──────────────────────────────

class SsmApiCorruptionTest : public ::testing::Test {
protected:
    ssm_handle* handle_ = nullptr;
    const char* path_ = "/data/data/com.termux/files/usr/tmp/opencode/ssm_integrity.db";

    void SetUp() override {
        ::remove(path_);
        ASSERT_EQ(ssm_init(&handle_, path_, nullptr, 0), SSM_OK);
        ASSERT_NE(handle_, nullptr);
        ASSERT_EQ(ssm_user_register(handle_, "alice", "strongP@ss1"), SSM_OK);
        const unsigned char priv[] = "sensitive-key-data-0000000000";
        ASSERT_EQ(ssm_secret_store(handle_, "alice", priv, sizeof(priv), nullptr, 0,
                                   "mykey", nullptr), SSM_OK);
    }

    void TearDown() override {
        if (handle_)
            ssm_destroy(handle_);
        ::remove(path_);
    }
};

TEST_F(SsmApiCorruptionTest, CorruptedTagReturnsIntegrityError) {
    // Tamper with the GCM auth tag directly in the database
    sqlite3* raw = nullptr;
    ASSERT_TRUE(db_open(path_, nullptr, 0, &raw));
    sqlite3_exec(raw,
        "UPDATE secrets SET tag = X'00000000000000000000000000000000' "
        "WHERE name = 'mykey'",
        nullptr, nullptr, nullptr);
    db_close(raw);

    // Re-open
    ssm_destroy(handle_);
    handle_ = nullptr;
    ASSERT_EQ(ssm_init(&handle_, path_, nullptr, 0), SSM_OK);

    unsigned char out[64] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "alice", "mykey", out, &len, nullptr, nullptr),
              SSM_ERR_INTEGRITY);
}

// ── Password validation ────────────────────────────────────────────────

TEST_F(SsmApiTest, DefaultValidatorRejectsShortPassword) {
    EXPECT_EQ(ssm_user_register(handle_, "shorty", "abc"), SSM_ERR_INTERNAL);
}

TEST_F(SsmApiTest, CustomValidator) {
    auto custom_check = [](const char* pw, void*) -> ssm_status {
        return std::strchr(pw, '!') ? SSM_OK : SSM_ERR_INTERNAL;
    };
    ssm_set_password_validator(custom_check, nullptr);

    EXPECT_EQ(ssm_user_register(handle_, "custom", "no-exclamation"), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_user_register(handle_, "custom2", "has-exclamation!"), SSM_OK);

    // Restore default
    ssm_set_password_validator(nullptr, nullptr);

    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(handle_, "custom2", "has-exclamation!", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);
}

TEST_F(SsmApiTest, ValidatorBlocksChangePassword) {
    ASSERT_EQ(ssm_user_register(handle_, "changeme", "longenoughpw"), SSM_OK);

    EXPECT_EQ(ssm_user_change_password(handle_, "changeme", "longenoughpw", "ab"),
              SSM_ERR_INTERNAL);
}

// ── Cache statistics ──────────────────────────────────────────────────

TEST_F(SsmApiTest, CacheStatsAfterOperations) {
    ASSERT_EQ(ssm_user_register(handle_, "alice", "password123"), SSM_OK);

    ssm_cache_stats stats{};
    EXPECT_EQ(ssm_cache_get_stats(handle_, &stats), SSM_OK);
    EXPECT_EQ(stats.total_entries, 256);
    EXPECT_GE(stats.miss_count, 0);
    EXPECT_GE(stats.hit_count, 0);

    // Store -> cache miss
    const unsigned char priv[] = "my-key-data-here-32bytes!";
    ASSERT_EQ(ssm_secret_store(handle_, "alice", priv, sizeof(priv), nullptr, 0,
                               "k", nullptr), SSM_OK);

    ssm_cache_stats after_store{};
    EXPECT_EQ(ssm_cache_get_stats(handle_, &after_store), SSM_OK);
    EXPECT_GT(after_store.miss_count, 0);

    // Get -> cache hit
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "alice", "k", out, &len, nullptr, nullptr), SSM_OK);

    EXPECT_EQ(ssm_cache_get_stats(handle_, &stats), SSM_OK);
    EXPECT_GT(stats.miss_count, 0);
    EXPECT_GT(stats.hit_count, 0);
}

// ── Concurrency ───────────────────────────────────────────────────────

TEST_F(SsmApiTest, ConcurrentOperations) {
    ASSERT_EQ(ssm_user_register(handle_, "alice", "pass1234"), SSM_OK);

    constexpr int N = 10;
    std::atomic<int> ok_count{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < N; ++i) {
        threads.emplace_back([this, i, &ok_count]() {
            char name[16];
            std::snprintf(name, sizeof(name), "key%d", i);
            unsigned char priv[16];
            std::memset(priv, 'A' + i, sizeof(priv));

            if (ssm_secret_store(handle_, "alice", priv, sizeof(priv), nullptr, 0,
                                 name, nullptr) == SSM_OK)
                ++ok_count;
        });
    }
    for (auto& t : threads)
        t.join();

    EXPECT_EQ(ok_count.load(), N);

    // retrieve all
    for (int i = 0; i < N; ++i) {
        char name[16];
        std::snprintf(name, sizeof(name), "key%d", i);
        unsigned char expected[16];
        std::memset(expected, 'A' + i, sizeof(expected));
        unsigned char out[16] = {};
        size_t len = sizeof(out);
        EXPECT_EQ(ssm_secret_get(handle_, "alice", name, out, &len, nullptr, nullptr), SSM_OK);
        EXPECT_EQ(std::memcmp(out, expected, sizeof(expected)), 0);
    }
}

TEST_F(SsmApiTest, ConcurrentPasswordChanges) {
    ASSERT_EQ(ssm_user_register(handle_, "bob", "origpass1"), SSM_OK);

    const unsigned char priv[] = "concurrent-access-key!";
    ASSERT_EQ(ssm_secret_store(handle_, "bob", priv, sizeof(priv), nullptr, 0,
                               "secret", nullptr), SSM_OK);

    std::vector<std::thread> threads;
    for (int i = 0; i < 3; ++i) {
        threads.emplace_back([this, i]() {
            char new_pw[32];
            std::snprintf(new_pw, sizeof(new_pw), "newpass%d_xxxxxxxxxx", i);
            ssm_user_change_password(handle_, "bob", "origpass1", new_pw);
        });
    }
    for (auto& t : threads)
        t.join();
}

// ── Audit log helpers and tests ────────────────────────────────────
//
// We use a file-based DB here so we can open a second connection to
// inspect the audit_log table.

static std::string audit_path() {
    return "/data/data/com.termux/files/usr/tmp/opencode/ssm_audit_test.db";
}

static int64_t audit_count(const char* path, const char* operation,
                            const char* result) {
    sqlite3* db = nullptr;
    if (!db_open(path, nullptr, 0, &db))
        return -1;
    int64_t cnt = 0;
    const char* sql =
        "SELECT count(*) FROM audit_log WHERE operation = ? AND result = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, operation, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, result, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            cnt = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);
    }
    db_close(db);
    return cnt;
}

static bool audit_has_details(const char* path, const char* operation,
                               const char* result, const char* details) {
    sqlite3* db = nullptr;
    if (!db_open(path, nullptr, 0, &db))
        return false;
    bool found = false;
    const char* sql =
        "SELECT count(*) FROM audit_log "
        "WHERE operation = ? AND result = ? AND details = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, operation, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, result, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, details, -1, SQLITE_TRANSIENT);
        found = (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int64(stmt, 0) > 0);
        sqlite3_finalize(stmt);
    }
    db_close(db);
    return found;
}

static bool audit_has_target(const char* path, const char* operation,
                              const char* result, const char* target) {
    sqlite3* db = nullptr;
    if (!db_open(path, nullptr, 0, &db))
        return false;
    bool found = false;
    const char* sql =
        "SELECT count(*) FROM audit_log "
        "WHERE operation = ? AND result = ? AND operation_target = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, operation, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, result, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, target, -1, SQLITE_TRANSIENT);
        found = (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int64(stmt, 0) > 0);
        sqlite3_finalize(stmt);
    }
    db_close(db);
    return found;
}

class AuditLogTest : public ::testing::Test {
protected:
    ssm_handle* handle_ = nullptr;
    const char* path_ = nullptr;

    void SetUp() override {
        path_ = strdup(audit_path().c_str());
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
        std::free(const_cast<char*>(path_));
    }
};

TEST_F(AuditLogTest, RegisterCreatesAuditRecord) {
    ASSERT_EQ(ssm_user_register(handle_, "audit_user", "p@ssw0rd"), SSM_OK);
    EXPECT_EQ(audit_count(path_, "user_register", "SSM_OK"), 1);
}

TEST_F(AuditLogTest, RegisterDuplicateHasDetails) {
    ASSERT_EQ(ssm_user_register(handle_, "dup", "p@ssw0rd"), SSM_OK);
    ASSERT_EQ(ssm_user_register(handle_, "dup", "p@ssw0rd"), SSM_ERR_AUTH);
    EXPECT_TRUE(audit_has_details(path_, "user_register", "SSM_ERR_AUTH",
                                    "{\"error\":\"username already exists\"}"));
}

TEST_F(AuditLogTest, AuthUnknownUserHasDetails) {
    int valid = 1;
    ssm_user_authenticate(handle_, "ghost", "x", &valid);
    EXPECT_TRUE(audit_has_details(path_, "user_authenticate", "SSM_ERR_AUTH",
                                    "{\"error\":\"user not found\"}"));
}

TEST_F(AuditLogTest, AuthWrongPasswordHasDetails) {
    ASSERT_EQ(ssm_user_register(handle_, "alice", "correct"), SSM_OK);
    int valid = 1;
    ssm_user_authenticate(handle_, "alice", "wrong", &valid);
    EXPECT_TRUE(audit_has_details(path_, "user_authenticate", "SSM_ERR_AUTH",
                                    "{\"error\":\"password mismatch\"}"));
}

TEST_F(AuditLogTest, SecretStoreHasTargetAndDetails) {
    ASSERT_EQ(ssm_user_register(handle_, "bob", "p@ss"), SSM_OK);
    const unsigned char priv[] = "test-key-data-here-32bytes!!";
    ASSERT_EQ(ssm_secret_store(handle_, "bob", priv, sizeof(priv), nullptr, 0,
                                "mykey", nullptr), SSM_OK);
    EXPECT_EQ(audit_count(path_, "secret_store", "SSM_OK"), 1);
    EXPECT_TRUE(audit_has_target(path_, "secret_store", "SSM_OK", "mykey"));
}

TEST_F(AuditLogTest, SecretGetHasTargetAndDetails) {
    ASSERT_EQ(ssm_user_register(handle_, "carol", "p@ss"), SSM_OK);
    const unsigned char priv[] = "get-test-key-data-here-32byte!";
    ASSERT_EQ(ssm_secret_store(handle_, "carol", priv, sizeof(priv), nullptr, 0,
                                "target-key", nullptr), SSM_OK);
    unsigned char out[64] = {};
    size_t len = sizeof(out);
    ASSERT_EQ(ssm_secret_get(handle_, "carol", "target-key", out, &len,
                              nullptr, nullptr), SSM_OK);
    EXPECT_TRUE(audit_has_target(path_, "secret_get", "SSM_OK", "target-key"));
}

TEST_F(AuditLogTest, SecretDeleteHasTargetAndDetails) {
    ASSERT_EQ(ssm_user_register(handle_, "dave", "p@ss"), SSM_OK);
    const unsigned char priv[] = "delete-test-key-data-32bytes!";
    ASSERT_EQ(ssm_secret_store(handle_, "dave", priv, sizeof(priv), nullptr, 0,
                                "del-key", nullptr), SSM_OK);
    ASSERT_EQ(ssm_secret_delete(handle_, "dave", "del-key"), SSM_OK);
    EXPECT_TRUE(audit_has_target(path_, "secret_delete", "SSM_OK", "del-key"));
}

TEST_F(AuditLogTest, ExpiredKekLogsTargetAndDetails) {
    ASSERT_EQ(ssm_user_register(handle_, "eve", "p@ss"), SSM_OK);
    const unsigned char priv[] = "expired-test-data-here-32byte!";
    ASSERT_EQ(ssm_secret_store(handle_, "eve", priv, sizeof(priv), nullptr, 0,
                                "exp-key", nullptr), SSM_OK);

    // expire the KEK via second connection
    ssm_destroy(handle_);
    handle_ = nullptr;
    {
        sqlite3* raw = nullptr;
        ASSERT_TRUE(db_open(path_, nullptr, 0, &raw));
        sqlite3_exec(raw,
            "UPDATE kek_metadata SET expires_at = '2020-01-01T00:00:00Z'",
            nullptr, nullptr, nullptr);
        db_close(raw);
    }
    ASSERT_EQ(ssm_init(&handle_, path_, nullptr, 0), SSM_OK);
    unsigned char buf[64] = {};
    size_t blen = sizeof(buf);
    ASSERT_EQ(ssm_secret_get(handle_, "eve", "exp-key", buf, &blen,
                              nullptr, nullptr), SSM_ERR_EXPIRED);

    EXPECT_TRUE(audit_has_target(path_, "secret_get", "SSM_ERR_EXPIRED",
                                  "exp-key"));
    EXPECT_TRUE(audit_has_details(path_, "secret_get", "SSM_ERR_EXPIRED",
                                    "{\"error\":\"KEK expired\"}"));
}

TEST_F(AuditLogTest, UserDeleteRecordsResult) {
    ASSERT_EQ(ssm_user_register(handle_, "frank", "p@ss"), SSM_OK);
    ASSERT_EQ(ssm_user_delete(handle_, "frank", "p@ss"), SSM_OK);
    EXPECT_EQ(audit_count(path_, "user_delete", "SSM_OK"), 1);
}

TEST_F(AuditLogTest, UserDeleteWrongPasswordHasDetails) {
    ASSERT_EQ(ssm_user_register(handle_, "grace", "correct"), SSM_OK);
    ASSERT_EQ(ssm_user_delete(handle_, "grace", "wrong"), SSM_ERR_AUTH);
    EXPECT_TRUE(audit_has_details(path_, "user_delete", "SSM_ERR_AUTH",
                                    "{\"error\":\"password mismatch\"}"));
}

TEST_F(AuditLogTest, KekRotateRecordsSuccess) {
    ASSERT_EQ(ssm_user_register(handle_, "heidi", "p@ss"), SSM_OK);
    ASSERT_EQ(ssm_kek_rotate(handle_, "heidi"), SSM_OK);
    EXPECT_EQ(audit_count(path_, "kek_rotate", "SSM_OK"), 1);
}

TEST_F(AuditLogTest, ChangePasswordRecordsResult) {
    ASSERT_EQ(ssm_user_register(handle_, "ivan", "oldpass"), SSM_OK);
    ASSERT_EQ(ssm_user_change_password(handle_, "ivan", "oldpass", "newpass123"), SSM_OK);
    EXPECT_EQ(audit_count(path_, "user_change_password", "SSM_OK"), 1);
}

TEST_F(AuditLogTest, SecretListRecordsResult) {
    ASSERT_EQ(ssm_user_register(handle_, "judy", "p@ss"), SSM_OK);
    auto cb = [](const char*, const char*, const char*, size_t, void*) {};
    ASSERT_EQ(ssm_secret_list(handle_, "judy", cb, nullptr), SSM_OK);
    EXPECT_EQ(audit_count(path_, "secret_list", "SSM_OK"), 1);
}

// ── Audit log query ──────────────────────────────────────────────

struct query_collector {
    std::vector<int64_t> ids;
    std::vector<std::string> operations;
    std::vector<std::string> targets;
    std::vector<std::string> details;
    std::vector<std::string> results;
};

static void query_cb(int64_t id, int64_t /*user_id*/, const char* username,
                      const char* operation, const char* target,
                      const char* details, const char* result,
                      const char* timestamp, void* user_data) {
    auto* c = static_cast<query_collector*>(user_data);
    (void)username; (void)timestamp;
    c->ids.push_back(id);
    c->operations.push_back(operation ? operation : "");
    c->targets.push_back(target ? target : "");
    c->details.push_back(details ? details : "");
    c->results.push_back(result ? result : "");
}

TEST_F(AuditLogTest, QueryAllReturnsEntries) {
    ASSERT_EQ(ssm_user_register(handle_, "query_user", "p@ss"), SSM_OK);
    const unsigned char priv[] = "test-key-data-32bytes!!";
    ASSERT_EQ(ssm_secret_store(handle_, "query_user", priv, sizeof(priv),
                                nullptr, 0, "qkey", nullptr), SSM_OK);

    query_collector c;
    EXPECT_EQ(ssm_audit_log_query(handle_, "query_user", nullptr, nullptr,
                                   100, 0, query_cb, &c), SSM_OK);
    EXPECT_GE(c.ids.size(), 2);
    bool found_register = false;
    bool found_store = false;
    for (auto& op : c.operations) {
        if (op == "user_register") found_register = true;
        if (op == "secret_store") found_store = true;
    }
    EXPECT_TRUE(found_register);
    EXPECT_TRUE(found_store);
}

TEST_F(AuditLogTest, QueryFilterByOperation) {
    ASSERT_EQ(ssm_user_register(handle_, "filter_user", "p@ss"), SSM_OK);
    ASSERT_EQ(ssm_kek_rotate(handle_, "filter_user"), SSM_OK);

    query_collector c;
    EXPECT_EQ(ssm_audit_log_query(handle_, "filter_user", "kek_rotate",
                                   nullptr, 100, 0, query_cb, &c), SSM_OK);
    EXPECT_EQ(c.operations.size(), 1);
    EXPECT_EQ(c.operations[0], "kek_rotate");
}

TEST_F(AuditLogTest, QueryFilterByResult) {
    ASSERT_EQ(ssm_user_register(handle_, "result_user", "p@ss"), SSM_OK);
    // trigger an error
    int valid = 0;
    ssm_user_authenticate(handle_, "result_user", "wrong", &valid);

    query_collector c;
    EXPECT_EQ(ssm_audit_log_query(handle_, "result_user", nullptr,
                                   "SSM_ERR_AUTH", 100, 0, query_cb, &c), SSM_OK);
    EXPECT_GE(c.ids.size(), 1);
    for (auto& res : c.results)
        EXPECT_EQ(res, "SSM_ERR_AUTH");
}

TEST_F(AuditLogTest, QueryRespectsLimit) {
    ASSERT_EQ(ssm_user_register(handle_, "limit_user", "p@ss"), SSM_OK);

    query_collector c;
    EXPECT_EQ(ssm_audit_log_query(handle_, "limit_user", nullptr, nullptr,
                                   0, 0, query_cb, &c), SSM_OK);
    EXPECT_LE(c.ids.size(), 1);  // limit 0 → default 100 → but only 1 entry
    (void)c;
}

TEST_F(AuditLogTest, NullHandleReturnsError) {
    EXPECT_EQ(ssm_audit_log_query(nullptr, "x", nullptr, nullptr, 10, 0,
                                   query_cb, nullptr), SSM_ERR_INTERNAL);
}

}  // namespace
}  // namespace ssm::v1

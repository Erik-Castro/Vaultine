#include "ssm/ssm.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "db/database.h"

#include "utils/secure_memory.h"

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
    ASSERT_EQ(ssm_user_register(handle_, "frank", "x"), SSM_OK);

    unsigned char out[8] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "frank", "nonexistent", out, &len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);
}

TEST_F(SsmApiTest, DeleteSecret) {
    ASSERT_EQ(ssm_user_register(handle_, "grace", "x"), SSM_OK);

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
    ASSERT_EQ(ssm_user_register(handle_, "hank", "x"), SSM_OK);
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
    ASSERT_EQ(ssm_user_register(handle_, "iris", "pw"), SSM_OK);

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
    ASSERT_EQ(ssm_user_register(handle_, "jack", "pw"), SSM_OK);

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
    EXPECT_EQ(ssm_user_change_password(handle_, "una", "wrong", "new"), SSM_ERR_AUTH);

    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(handle_, "una", "realpw", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);
}

TEST_F(SsmApiTest, ChangePasswordEmptyPassword) {
    ASSERT_EQ(ssm_user_register(handle_, "trent", "pw"), SSM_OK);
    EXPECT_EQ(ssm_user_change_password(handle_, "trent", "pw", ""), SSM_ERR_INTERNAL);
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
    ASSERT_EQ(ssm_user_register(handle_, "xavier", "pw"), SSM_OK);

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
    ASSERT_EQ(ssm_user_register(handle_, "walter", "pw"), SSM_OK);
    const unsigned char priv[] = "some-key";
    ASSERT_EQ(ssm_secret_store(handle_, "walter", priv, sizeof(priv), nullptr, 0,
                               "k", nullptr), SSM_OK);

    // destroy and re-open to test with a file DB for expired KEK manipulation
    ssm_destroy(handle_);
    handle_ = nullptr;

    const char* path = "/data/data/com.termux/files/usr/tmp/opencode/ssm_list_expired.db";
    ::remove(path);
    ASSERT_EQ(ssm_init(&handle_, path, nullptr, 0), SSM_OK);
    ASSERT_EQ(ssm_user_register(handle_, "walter", "pw"), SSM_OK);
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

}  // namespace
}  // namespace ssm::v1

#include <gtest/gtest.h>

#include "ssm/ssm.h"
#include "utils/secure_memory.h"

#include <cstring>
#include <vector>

namespace ssm::v1 {
namespace {

class SsmApiTest : public ::testing::Test
{
protected:
    ssm_handle* handle_ = nullptr;

    void SetUp() override
    {
        ASSERT_EQ(ssm_init(&handle_, ":memory:", nullptr, 0), SSM_OK);
        ASSERT_NE(handle_, nullptr);
    }

    void TearDown() override
    {
        if (handle_)
            ssm_destroy(handle_);
    }
};

TEST_F(SsmApiTest, RegisterAndAuthenticate)
{
    EXPECT_EQ(ssm_user_register(handle_, "alice", "p@ssw0rd"), SSM_OK);

    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(handle_, "alice", "p@ssw0rd", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);
}

TEST_F(SsmApiTest, AuthenticateWrongPassword)
{
    ASSERT_EQ(ssm_user_register(handle_, "bob", "secret"), SSM_OK);

    int valid = 1;
    EXPECT_EQ(ssm_user_authenticate(handle_, "bob", "wrong", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);
}

TEST_F(SsmApiTest, AuthenticateUnknownUser)
{
    int valid = 1;
    EXPECT_EQ(ssm_user_authenticate(handle_, "nobody", "x", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);
}

TEST_F(SsmApiTest, DuplicateRegistrationFails)
{
    ASSERT_EQ(ssm_user_register(handle_, "carol", "pass"), SSM_OK);
    EXPECT_EQ(ssm_user_register(handle_, "carol", "pass"), SSM_ERR_AUTH);
}

TEST_F(SsmApiTest, StoreAndGetSecret)
{
    ASSERT_EQ(ssm_user_register(handle_, "dave", "p@ss"), SSM_OK);

    const unsigned char priv[] = "my-ecdsa-private-key-32bytes!!";
    EXPECT_EQ(ssm_secret_store(handle_, "dave",
                               priv, sizeof(priv),
                               nullptr, 0,
                               "key1", "my first key"),
              SSM_OK);

    unsigned char priv_out[64] = {};
    size_t priv_len = sizeof(priv_out);
    EXPECT_EQ(ssm_secret_get(handle_, "dave", "key1",
                             priv_out, &priv_len,
                             nullptr, nullptr),
              SSM_OK);
    EXPECT_EQ(priv_len, sizeof(priv));
    EXPECT_EQ(std::memcmp(priv_out, priv, sizeof(priv)), 0);
}

TEST_F(SsmApiTest, StoreAndGetSecretWithPublicKey)
{
    ASSERT_EQ(ssm_user_register(handle_, "eve", "s3cret"), SSM_OK);

    const unsigned char priv[] = "private-key-blob-here-32bytes!";
    const unsigned char pub[] = "public-key-blob-here-28bytes!";
    EXPECT_EQ(ssm_secret_store(handle_, "eve",
                               priv, sizeof(priv),
                               pub, sizeof(pub),
                               "keypair", "with pub"),
              SSM_OK);

    unsigned char priv_out[64] = {};
    size_t priv_len = sizeof(priv_out);
    unsigned char pub_out[64] = {};
    size_t pub_len = sizeof(pub_out);
    EXPECT_EQ(ssm_secret_get(handle_, "eve", "keypair",
                             priv_out, &priv_len,
                             pub_out, &pub_len),
              SSM_OK);
    EXPECT_EQ(priv_len, sizeof(priv));
    EXPECT_EQ(pub_len, sizeof(pub));
    EXPECT_EQ(std::memcmp(priv_out, priv, sizeof(priv)), 0);
    EXPECT_EQ(std::memcmp(pub_out, pub, sizeof(pub)), 0);
}

TEST_F(SsmApiTest, GetNonExistentSecret)
{
    ASSERT_EQ(ssm_user_register(handle_, "frank", "x"), SSM_OK);

    unsigned char out[8] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "frank", "nonexistent",
                             out, &len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);
}

TEST_F(SsmApiTest, DeleteSecret)
{
    ASSERT_EQ(ssm_user_register(handle_, "grace", "x"), SSM_OK);

    const unsigned char priv[] = "delete-me-key";
    ASSERT_EQ(ssm_secret_store(handle_, "grace",
                               priv, sizeof(priv),
                               nullptr, 0,
                               "temp", "will delete"),
              SSM_OK);

    EXPECT_EQ(ssm_secret_delete(handle_, "grace", "temp"), SSM_OK);

    unsigned char out[16] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "grace", "temp",
                             out, &len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);
}

TEST_F(SsmApiTest, DeleteNonExistentSecret)
{
    ASSERT_EQ(ssm_user_register(handle_, "hank", "x"), SSM_OK);
    EXPECT_EQ(ssm_secret_delete(handle_, "hank", "ghost"), SSM_ERR_NOT_FOUND);
}

TEST_F(SsmApiTest, RotateAndSecretsStillAccessible)
{
    ASSERT_EQ(ssm_user_register(handle_, "ivy", "mypass"), SSM_OK);

    const unsigned char priv[] = "important-key-never-lose-32byte!";
    ASSERT_EQ(ssm_secret_store(handle_, "ivy",
                               priv, sizeof(priv),
                               nullptr, 0,
                               "critical", "test"),
              SSM_OK);

    EXPECT_EQ(ssm_kek_rotate(handle_, "ivy"), SSM_OK);

    unsigned char priv_out[64] = {};
    size_t priv_len = sizeof(priv_out);
    EXPECT_EQ(ssm_secret_get(handle_, "ivy", "critical",
                             priv_out, &priv_len,
                             nullptr, nullptr),
              SSM_OK);
    EXPECT_EQ(priv_len, sizeof(priv));
    EXPECT_EQ(std::memcmp(priv_out, priv, sizeof(priv)), 0);
}

TEST_F(SsmApiTest, RotateMultipleSecrets)
{
    ASSERT_EQ(ssm_user_register(handle_, "jack", "pw"), SSM_OK);

    for (int i = 0; i < 5; ++i)
    {
        unsigned char priv[16];
        std::memset(priv, 'A' + i, sizeof(priv));
        char name[8];
        std::snprintf(name, sizeof(name), "k%d", i);
        ASSERT_EQ(ssm_secret_store(handle_, "jack",
                                   priv, sizeof(priv),
                                   nullptr, 0,
                                   name, nullptr),
                  SSM_OK);
    }

    ASSERT_EQ(ssm_kek_rotate(handle_, "jack"), SSM_OK);

    for (int i = 0; i < 5; ++i)
    {
        unsigned char expected[16];
        std::memset(expected, 'A' + i, sizeof(expected));
        unsigned char out[16] = {};
        size_t out_len = sizeof(out);
        char name[8];
        std::snprintf(name, sizeof(name), "k%d", i);
        ASSERT_EQ(ssm_secret_get(handle_, "jack", name,
                                 out, &out_len, nullptr, nullptr),
                  SSM_OK);
        EXPECT_EQ(out_len, sizeof(expected));
        EXPECT_EQ(std::memcmp(out, expected, sizeof(expected)), 0);
    }
}

TEST_F(SsmApiTest, UserIsolation)
{
    ASSERT_EQ(ssm_user_register(handle_, "user1", "pass1"), SSM_OK);
    ASSERT_EQ(ssm_user_register(handle_, "user2", "pass2"), SSM_OK);

    const unsigned char priv[] = "user1-private-key-data-here!";
    ASSERT_EQ(ssm_secret_store(handle_, "user1",
                               priv, sizeof(priv),
                               nullptr, 0,
                               "mykey", nullptr),
              SSM_OK);

    unsigned char out[64] = {};
    size_t len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(handle_, "user2", "mykey",
                             out, &len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);
}

TEST_F(SsmApiTest, RotateNonExistentUser)
{
    int valid = 0;
    ASSERT_EQ(ssm_user_authenticate(handle_, "ghost", "x", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);

    EXPECT_EQ(ssm_kek_rotate(handle_, "ghost"), SSM_ERR_AUTH);
}

TEST_F(SsmApiTest, NullHandleReturnsError)
{
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
    EXPECT_EQ(ssm_kek_rotate(nullptr, "a"), SSM_ERR_INTERNAL);
}

} // namespace
} // namespace ssm::v1

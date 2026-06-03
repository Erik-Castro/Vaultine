#include "ssm/ssm.h"

#include <gtest/gtest.h>
#include <sqlcipher.h>

#include <cstring>
#include <string>
#include <vector>

#include "export/export.h"

namespace ssm::v1 {
namespace {

class ExportTest : public ::testing::Test {
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

struct export_chunk {
    std::string data;
};

static void collect_chunk(const char* chunk, size_t len, void* user_data) {
    auto* buf = static_cast<std::string*>(user_data);
    buf->append(chunk, len);
}

TEST_F(ExportTest, ExportJsonEmptyDb) {
    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_JSON, 0, collect_chunk, &out), SSM_OK);
    EXPECT_EQ(out, "{\"users\":[],\"secrets\":[],\"kek_metadata\":[]}");
}

TEST_F(ExportTest, ExportCsvEmptyDb) {
    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_CSV, 0, collect_chunk, &out), SSM_OK);
    EXPECT_NE(out.find("=== users ==="), std::string::npos);
    EXPECT_EQ(out.find("redacted"), std::string::npos);
}

TEST_F(ExportTest, ExportJsonAfterRegistration) {
    ASSERT_EQ(ssm_user_register(handle_, "alice", "p@ssw0rd"), SSM_OK);

    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_JSON, 0, collect_chunk, &out), SSM_OK);
    EXPECT_NE(out.find("\"username\":\"alice\""), std::string::npos);
    EXPECT_NE(out.find("\"created_at\":"), std::string::npos);
    EXPECT_NE(out.find("\"users\":"), std::string::npos);
}

TEST_F(ExportTest, ExportJsonAfterSecretStore) {
    ASSERT_EQ(ssm_user_register(handle_, "bob", "s3cret"), SSM_OK);
    const unsigned char key[] = "test-private-key-data-32bytes!";
    ASSERT_EQ(ssm_secret_store(handle_, "bob", key, sizeof(key), nullptr, 0, "mykey", "desc"),
              SSM_OK);

    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_JSON, 0, collect_chunk, &out), SSM_OK);
    EXPECT_NE(out.find("\"name\":\"mykey\""), std::string::npos);
    EXPECT_NE(out.find("\"size\":31"), std::string::npos);
    EXPECT_NE(out.find("\"has_pub\":false"), std::string::npos);
    EXPECT_NE(out.find("\"description\":\"desc\""), std::string::npos);
    EXPECT_NE(out.find("\"user\":\"bob\""), std::string::npos);
}

TEST_F(ExportTest, ExportJsonWithPublicKey) {
    ASSERT_EQ(ssm_user_register(handle_, "carol", "p@ss"), SSM_OK);
    const unsigned char priv[] = "private-key-blob-32bytes!!!!!!!";
    const unsigned char pub[] = "public-key-blob-here!";
    ASSERT_EQ(ssm_secret_store(handle_, "carol", priv, sizeof(priv), pub, sizeof(pub), "kp", ""),
              SSM_OK);

    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_JSON, 0, collect_chunk, &out), SSM_OK);
    EXPECT_NE(out.find("\"has_pub\":true"), std::string::npos);
}

TEST_F(ExportTest, ExportRedactPii) {
    ASSERT_EQ(ssm_user_register(handle_, "alice", "p@ss"), SSM_OK);
    ASSERT_EQ(ssm_user_register(handle_, "bob", "p@ss"), SSM_OK);

    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_JSON, 1, collect_chunk, &out), SSM_OK);
    EXPECT_EQ(out.find("\"alice\""), std::string::npos);
    EXPECT_EQ(out.find("\"bob\""), std::string::npos);
    EXPECT_NE(out.find("\"user_1\""), std::string::npos);
    EXPECT_NE(out.find("\"user_2\""), std::string::npos);
}

TEST_F(ExportTest, ExportCsvAfterRegistration) {
    ASSERT_EQ(ssm_user_register(handle_, "dave", "pass"), SSM_OK);

    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_CSV, 0, collect_chunk, &out), SSM_OK);
    EXPECT_NE(out.find("dave,"), std::string::npos);
    EXPECT_NE(out.find("username,created_at"), std::string::npos);
}

TEST_F(ExportTest, ExportCsvRedactPii) {
    ASSERT_EQ(ssm_user_register(handle_, "eve", "pass"), SSM_OK);

    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_CSV, 1, collect_chunk, &out), SSM_OK);
    EXPECT_EQ(out.find("eve,"), std::string::npos);
    EXPECT_NE(out.find("user_1,"), std::string::npos);
}

TEST_F(ExportTest, NullParamsFail) {
    EXPECT_EQ(ssm_export(nullptr, SSM_EXPORT_JSON, 0, collect_chunk, nullptr), SSM_ERR_INTERNAL);
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_JSON, 0, nullptr, nullptr), SSM_ERR_INTERNAL);
}

TEST_F(ExportTest, ExportJsonWithKekMetadata) {
    ASSERT_EQ(ssm_user_register(handle_, "frank", "p@ss"), SSM_OK);
    ASSERT_EQ(ssm_kek_rotate(handle_, "frank"), SSM_OK);

    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_JSON, 0, collect_chunk, &out), SSM_OK);
    EXPECT_NE(out.find("\"kek_metadata\":"), std::string::npos);
    EXPECT_NE(out.find("\"version\":"), std::string::npos);
    EXPECT_NE(out.find("\"expires_at\":"), std::string::npos);
}

TEST_F(ExportTest, ExportKeepsSecretsPrivate) {
    // Verify the export does NOT contain private key BLOBs
    ASSERT_EQ(ssm_user_register(handle_, "grace", "p@ss"), SSM_OK);
    const unsigned char secret[] = "my-super-secret-data-dont-expose!";
    ASSERT_EQ(ssm_secret_store(handle_, "grace", secret, sizeof(secret), nullptr, 0, "secret1", ""),
              SSM_OK);

    std::string out;
    EXPECT_EQ(ssm_export(handle_, SSM_EXPORT_JSON, 0, collect_chunk, &out), SSM_OK);
    EXPECT_EQ(out.find("my-super-secret-data"), std::string::npos);
    EXPECT_EQ(out.find("private_key"), std::string::npos);
}

}  // namespace
}  // namespace ssm::v1

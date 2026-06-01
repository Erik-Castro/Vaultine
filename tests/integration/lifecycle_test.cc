#include "ssm/ssm.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <vector>

namespace ssm::v1 {
namespace {

struct Lifecycle {
    std::vector<std::string> names;
    std::vector<std::string> descs;
};

void lifecycle_cb(const char* name, const char* desc, const char* updated_at,
                  size_t pub_key_len, void* user_data) {
    auto* lc = static_cast<Lifecycle*>(user_data);
    lc->names.push_back(name ? name : "");
    lc->descs.push_back(desc ? desc : "");
    (void)updated_at;
    (void)pub_key_len;
}

TEST(LifecycleIntegration, FullLifecycle) {
    const char* path = "/data/data/com.termux/files/usr/tmp/opencode/ssm_lifecycle.db";
    ::remove(path);

    ssm_handle* h = nullptr;
    ASSERT_EQ(ssm_init(&h, path, nullptr, 0), SSM_OK);
    ASSERT_NE(h, nullptr);

    // 1. register two users
    ASSERT_EQ(ssm_user_register(h, "alice", "alice_pass"), SSM_OK);
    ASSERT_EQ(ssm_user_register(h, "bob", "bob_pass"), SSM_OK);

    // 2. authenticate both
    int valid = 0;
    EXPECT_EQ(ssm_user_authenticate(h, "alice", "alice_pass", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);
    EXPECT_EQ(ssm_user_authenticate(h, "bob", "bob_pass", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);

    // 3. store secrets for alice
    unsigned char a_priv[] = "alice-ecdsa-private-key-32b!!";
    unsigned char a_pub[]  = "alice-public-key-here-28b!!";
    ASSERT_EQ(ssm_secret_store(h, "alice", a_priv, sizeof(a_priv), a_pub, sizeof(a_pub),
                               "ecdsa-key", "ECDSA keypair"), SSM_OK);
    ASSERT_EQ(ssm_secret_store(h, "alice", a_priv, sizeof(a_priv), nullptr, 0,
                               "backup-seed", "BIP39 seed"), SSM_OK);

    // 4. store secrets for bob
    unsigned char b_priv[] = "bob-ed25519-private-key!!";
    ASSERT_EQ(ssm_secret_store(h, "bob", b_priv, sizeof(b_priv), nullptr, 0,
                               "ed25519", "Ed25519 signing key"), SSM_OK);

    // 5. verify tenant isolation
    unsigned char out[64];
    size_t out_len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(h, "bob", "ecdsa-key", out, &out_len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);

    // 6. list alice secrets
    Lifecycle lc_alice;
    EXPECT_EQ(ssm_secret_list(h, "alice", lifecycle_cb, &lc_alice), SSM_OK);
    EXPECT_EQ(lc_alice.names.size(), 2);

    // 7. rotate alice KEK
    EXPECT_EQ(ssm_kek_rotate(h, "alice"), SSM_OK);

    // 8. alice secrets still accessible after rotation
    out_len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(h, "alice", "ecdsa-key", out, &out_len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(out_len, sizeof(a_priv));
    EXPECT_EQ(std::memcmp(out, a_priv, sizeof(a_priv)), 0);

    // 9. change bob's password
    EXPECT_EQ(ssm_user_change_password(h, "bob", "bob_pass", "bob_new_pass"), SSM_OK);

    // 10. bob's old password fails, new works
    valid = 1;
    EXPECT_EQ(ssm_user_authenticate(h, "bob", "bob_pass", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);
    EXPECT_EQ(ssm_user_authenticate(h, "bob", "bob_new_pass", &valid), SSM_OK);
    EXPECT_EQ(valid, 1);

    // 11. bob's secret still accessible after password change
    out_len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(h, "bob", "ed25519", out, &out_len, nullptr, nullptr), SSM_OK);
    EXPECT_EQ(out_len, sizeof(b_priv));
    EXPECT_EQ(std::memcmp(out, b_priv, sizeof(b_priv)), 0);

    // 12. delete one of alice's secrets
    EXPECT_EQ(ssm_secret_delete(h, "alice", "backup-seed"), SSM_OK);
    EXPECT_EQ(ssm_secret_get(h, "alice", "backup-seed", out, &out_len, nullptr, nullptr),
              SSM_ERR_NOT_FOUND);

    // 13. delete bob (cascade removes all bob's data)
    EXPECT_EQ(ssm_user_delete(h, "bob", "bob_new_pass"), SSM_OK);
    EXPECT_EQ(ssm_user_authenticate(h, "bob", "bob_new_pass", &valid), SSM_OK);
    EXPECT_EQ(valid, 0);

    // 14. alice still intact after bob deletion
    out_len = sizeof(out);
    EXPECT_EQ(ssm_secret_get(h, "alice", "ecdsa-key", out, &out_len, nullptr, nullptr), SSM_OK);

    ssm_destroy(h);
    ::remove(path);
}

}  // namespace
}  // namespace ssm::v1

#include <gtest/gtest.h>

#include <cstring>

#include "crypto/random.h"
#include "crypto/aes_kw.h"

namespace ssm::v1 {
namespace {

static constexpr size_t KEK_LEN = 32;
static constexpr size_t KEY_LEN = 32;

TEST(AesKwTest, WrapUnwrapRoundTrip)
{
    unsigned char kek[KEK_LEN];
    unsigned char key[KEY_LEN];
    random_bytes(kek, sizeof(kek));
    random_bytes(key, sizeof(key));

    unsigned char wrapped[64];
    size_t wrapped_len = 0;

    ASSERT_TRUE(aes_kw_wrap(key, sizeof(key), kek, sizeof(kek),
                            wrapped, &wrapped_len));
    EXPECT_EQ(wrapped_len, KEY_LEN + 8);

    unsigned char unwrapped[KEY_LEN];
    size_t unwrapped_len = 0;

    ASSERT_TRUE(aes_kw_unwrap(wrapped, wrapped_len, kek, sizeof(kek),
                              unwrapped, &unwrapped_len));
    EXPECT_EQ(unwrapped_len, KEY_LEN);
    EXPECT_EQ(std::memcmp(key, unwrapped, KEY_LEN), 0);
}

TEST(AesKwTest, WrongKekFailsUnwrap)
{
    unsigned char kek_a[KEK_LEN];
    unsigned char kek_b[KEK_LEN];
    unsigned char key[KEY_LEN];
    random_bytes(kek_a, sizeof(kek_a));
    random_bytes(kek_b, sizeof(kek_b));
    random_bytes(key, sizeof(key));

    unsigned char wrapped[64];
    size_t wrapped_len = 0;

    ASSERT_TRUE(aes_kw_wrap(key, sizeof(key), kek_a, sizeof(kek_a),
                            wrapped, &wrapped_len));

    unsigned char unwrapped[KEY_LEN];
    size_t unwrapped_len = 0;

    EXPECT_FALSE(aes_kw_unwrap(wrapped, wrapped_len, kek_b, sizeof(kek_b),
                               unwrapped, &unwrapped_len));
}

TEST(AesKwTest, RejectsInvalidKeyLengths)
{
    unsigned char small_kek[16]; // 128-bit, not 256
    unsigned char key[KEY_LEN];
    unsigned char wrapped[64];
    size_t wrapped_len = 0;

    EXPECT_FALSE(aes_kw_wrap(key, sizeof(key), small_kek, sizeof(small_kek),
                             wrapped, &wrapped_len));
}

TEST(AesKwTest, RejectsNonAlignedPlaintext)
{
    unsigned char kek[KEK_LEN];
    unsigned char bad_input[3];
    unsigned char wrapped[64];
    size_t wrapped_len = 0;
    random_bytes(kek, sizeof(kek));

    EXPECT_FALSE(aes_kw_wrap(bad_input, sizeof(bad_input), kek, sizeof(kek),
                             wrapped, &wrapped_len));
}

TEST(AesKwTest, WrapSmallKey)
{
    unsigned char kek[KEK_LEN];
    unsigned char key[16]; // 128-bit key
    random_bytes(kek, sizeof(kek));
    random_bytes(key, sizeof(key));

    unsigned char wrapped[32];
    size_t wrapped_len = 0;

    ASSERT_TRUE(aes_kw_wrap(key, sizeof(key), kek, sizeof(kek),
                            wrapped, &wrapped_len));
    EXPECT_EQ(wrapped_len, sizeof(key) + 8);

    unsigned char unwrapped[16];
    size_t unwrapped_len = 0;

    ASSERT_TRUE(aes_kw_unwrap(wrapped, wrapped_len, kek, sizeof(kek),
                              unwrapped, &unwrapped_len));
    EXPECT_EQ(unwrapped_len, sizeof(key));
    EXPECT_EQ(std::memcmp(key, unwrapped, sizeof(key)), 0);
}

} // namespace
} // namespace ssm::v1

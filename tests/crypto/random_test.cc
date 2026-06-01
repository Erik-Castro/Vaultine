#include <gtest/gtest.h>

#include <algorithm>
#include <numeric>
#include <set>

#include "crypto/random.h"

namespace ssm::v1 {
namespace {

TEST(RandomTest, FillsBufferWithNonZero)
{
    unsigned char buf[32]{};
    random_bytes(buf, sizeof(buf));
    bool all_zero = std::all_of(buf, buf + sizeof(buf),
                                [](auto b) { return b == 0; });
    EXPECT_FALSE(all_zero);
}

TEST(RandomTest, ProducesDifferentOutputs)
{
    unsigned char a[16]{};
    unsigned char b[16]{};
    random_bytes(a, sizeof(a));
    random_bytes(b, sizeof(b));
    EXPECT_NE(std::memcmp(a, b, sizeof(a)), 0);
}

TEST(RandomTest, ZeroLengthIsNoOp)
{
    unsigned char buf[4]{0xAA, 0xBB, 0xCC, 0xDD};
    unsigned char copy[4];
    std::memcpy(copy, buf, sizeof(buf));
    random_bytes(buf, 0);
    EXPECT_EQ(std::memcmp(buf, copy, sizeof(buf)), 0);
}

TEST(RandomTest, LargeBufferIsDifferentiable)
{
    unsigned char buf[4096]{};
    random_bytes(buf, sizeof(buf));
    auto sum = std::accumulate(buf, buf + sizeof(buf), 0ULL);
    EXPECT_NE(sum, 0);
}

} // namespace
} // namespace ssm::v1

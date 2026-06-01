#include <gtest/gtest.h>

#include <cstring>

#include "utils/secure_memory.h"

namespace ssm::v1 {
namespace {

TEST(SecureMemoryTest, EraseZeroesBuffer)
{
    unsigned char buf[32];
    std::memset(buf, 0xFF, sizeof(buf));
    secure_erase(buf, sizeof(buf));
    for (auto b : buf)
        EXPECT_EQ(b, 0);
}

TEST(SecureMemoryTest, EraseNullIsSafe)
{
    secure_erase(nullptr, 0);
}

TEST(SecureMemoryTest, EraseZeroLengthIsSafe)
{
    int x = 42;
    secure_erase(&x, 0);
    EXPECT_EQ(x, 42);
}

TEST(SecureMemoryTest, EraseTemplateTrivialType)
{
    struct alignas(16) pod
    {
        int a;
        double b;
    };
    pod p{42, 3.14};
    secure_erase(p);
    EXPECT_EQ(p.a, 0);
    EXPECT_EQ(p.b, 0.0);
}

TEST(SecureVectorTest, DefaultEmpty)
{
    secure_vector<int> v;
    EXPECT_TRUE(v.empty());
    EXPECT_EQ(v.size(), 0);
    EXPECT_EQ(v.data(), nullptr);
}

TEST(SecureVectorTest, AllocAndAccess)
{
    secure_vector<int> v(16);
    EXPECT_FALSE(v.empty());
    EXPECT_EQ(v.size(), 16);
    v[0] = 42;
    EXPECT_EQ(v[0], 42);
    v[15] = -1;
    EXPECT_EQ(v[15], -1);
}

TEST(SecureVectorTest, MoveClearsSource)
{
    secure_vector<int> v(8);
    v[3] = 99;
    auto v2 = std::move(v);
    EXPECT_TRUE(v.empty());
    EXPECT_EQ(v.size(), 0);
    EXPECT_EQ(v.data(), nullptr);
    EXPECT_EQ(v2.size(), 8);
    EXPECT_EQ(v2[3], 99);
}

TEST(SecureVectorTest, MoveAssignmentReleasesTarget)
{
    secure_vector<int> a(4);
    a[0] = 10;
    secure_vector<int> b(2);
    b[0] = 20;
    b = std::move(a);
    EXPECT_EQ(b[0], 10);
    EXPECT_EQ(b.size(), 4);
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(a.data(), nullptr);
}

TEST(SecureVectorTest, ResizePreservesContent)
{
    secure_vector<int> v(4);
    v[0] = 1;
    v[1] = 2;
    v.resize(8);
    EXPECT_EQ(v[0], 1);
    EXPECT_EQ(v[1], 2);
    EXPECT_EQ(v.size(), 8);
    EXPECT_NE(v.data(), nullptr);
}

TEST(SecureVectorTest, ResizeShrinks)
{
    secure_vector<int> v(8);
    for (int i = 0; i < 8; ++i)
        v[i] = i;
    v.resize(3);
    EXPECT_EQ(v.size(), 3);
    EXPECT_EQ(v[0], 0);
    EXPECT_EQ(v[1], 1);
    EXPECT_EQ(v[2], 2);
}

TEST(SecureVectorDeathTest, StaticAssertNonTrivial)
{
    EXPECT_FALSE(std::is_trivially_copyable_v<std::string>);
}

} // namespace
} // namespace ssm::v1

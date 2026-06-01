#include "utils/secure_memory.h"

#include <gtest/gtest.h>

#include <cstring>

namespace ssm::v1 {
namespace {

TEST(SecureMemoryTest, EraseZeroesBuffer) {
    unsigned char buf[32];
    std::memset(buf, 0xFF, sizeof(buf));
    secure_erase(buf, sizeof(buf));
    for (auto b : buf)
        EXPECT_EQ(b, 0);
}

TEST(SecureMemoryTest, EraseNullIsSafe) { secure_erase(nullptr, 0); }

TEST(SecureMemoryTest, EraseZeroLengthIsSafe) {
    int x = 42;
    secure_erase(&x, 0);
    EXPECT_EQ(x, 42);
}

TEST(SecureMemoryTest, EraseTemplateTrivialType) {
    struct alignas(16) pod {
        int a;
        double b;
    };
    pod p{42, 3.14};
    secure_erase(p);
    EXPECT_EQ(p.a, 0);
    EXPECT_EQ(p.b, 0.0);
}

TEST(SecureVectorTest, DefaultEmpty) {
    secure_vector<int> v;
    EXPECT_TRUE(v.empty());
    EXPECT_EQ(v.size(), 0);
    EXPECT_EQ(v.data(), nullptr);
}

TEST(SecureVectorTest, AllocAndAccess) {
    secure_vector<int> v(16);
    EXPECT_FALSE(v.empty());
    EXPECT_EQ(v.size(), 16);
    v[0] = 42;
    EXPECT_EQ(v[0], 42);
    v[15] = -1;
    EXPECT_EQ(v[15], -1);
}

TEST(SecureVectorTest, MoveClearsSource) {
    secure_vector<int> v(8);
    v[3] = 99;
    auto v2 = std::move(v);
    EXPECT_TRUE(v.empty());
    EXPECT_EQ(v.size(), 0);
    EXPECT_EQ(v.data(), nullptr);
    EXPECT_EQ(v2.size(), 8);
    EXPECT_EQ(v2[3], 99);
}

TEST(SecureVectorTest, MoveAssignmentReleasesTarget) {
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

TEST(SecureVectorTest, ResizePreservesContent) {
    secure_vector<int> v(4);
    v[0] = 1;
    v[1] = 2;
    v.resize(8);
    EXPECT_EQ(v[0], 1);
    EXPECT_EQ(v[1], 2);
    EXPECT_EQ(v.size(), 8);
    EXPECT_NE(v.data(), nullptr);
}

TEST(SecureVectorTest, ResizeShrinks) {
    secure_vector<int> v(8);
    for (int i = 0; i < 8; ++i)
        v[i] = i;
    v.resize(3);
    EXPECT_EQ(v.size(), 3);
    EXPECT_EQ(v[0], 0);
    EXPECT_EQ(v[1], 1);
    EXPECT_EQ(v[2], 2);
}

TEST(SecureVectorDeathTest, StaticAssertNonTrivial) {
    EXPECT_FALSE(std::is_trivially_copyable_v<std::string>);
}

// -------------------------------------------------------------------
// secure_alloc / secure_free tests
// -------------------------------------------------------------------
TEST(SecureAllocTest, ZeroSizeReturnsNull) {
    EXPECT_EQ(secure_alloc(0), nullptr);
}

TEST(SecureAllocTest, AllocReturnsNonNull) {
    auto* p = secure_alloc(64);
    ASSERT_NE(p, nullptr);
    secure_free(p, 64);
}

TEST(SecureAllocTest, AllocMemoryIsWritable) {
    auto* p = static_cast<unsigned char*>(secure_alloc(128));
    ASSERT_NE(p, nullptr);
    std::memset(p, 0xA5, 128);
    for (int i = 0; i < 128; ++i)
        EXPECT_EQ(p[i], 0xA5);
    secure_free(p, 128);
}

TEST(SecureAllocTest, FreeNullIsSafe) {
    secure_free(nullptr, 0);
}

TEST(SecureAllocTest, FreeNullWithSizeIsSafe) {
    secure_free(nullptr, 64);
}

TEST(SecureAllocTest, MultipleAllocs) {
    auto* a = secure_alloc(32);
    auto* b = secure_alloc(64);
    auto* c = secure_alloc(128);
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    ASSERT_NE(c, nullptr);
    EXPECT_NE(a, b);
    EXPECT_NE(b, c);
    secure_free(a, 32);
    secure_free(b, 64);
    secure_free(c, 128);
}

// -------------------------------------------------------------------
// secure_buffer tests
// -------------------------------------------------------------------
TEST(SecureBufferTest, DefaultEmpty) {
    secure_buffer<int> buf;
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.data(), nullptr);
    EXPECT_FALSE(static_cast<bool>(buf));
}

TEST(SecureBufferTest, AllocWithCount) {
    secure_buffer<int> buf(16);
    EXPECT_FALSE(buf.empty());
    EXPECT_EQ(buf.size(), 16);
    ASSERT_NE(buf.data(), nullptr);
    EXPECT_NE(static_cast<bool>(buf), false);
}

TEST(SecureBufferTest, IndexAccess) {
    secure_buffer<int> buf(8);
    buf[0] = 42;
    buf[7] = -1;
    EXPECT_EQ(buf[0], 42);
    EXPECT_EQ(buf[7], -1);
}

TEST(SecureBufferTest, IteratorRange) {
    secure_buffer<int> buf(4);
    buf[0] = 10;
    buf[1] = 20;
    buf[2] = 30;
    buf[3] = 40;
    int sum = 0;
    for (auto it = buf.begin(); it != buf.end(); ++it)
        sum += *it;
    EXPECT_EQ(sum, 100);
}

TEST(SecureBufferTest, MoveClearsSource) {
    secure_buffer<int> buf(8);
    buf[3] = 99;
    auto buf2 = std::move(buf);
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.data(), nullptr);
    EXPECT_EQ(buf2.size(), 8);
    EXPECT_EQ(buf2[3], 99);
}

TEST(SecureBufferTest, MoveAssignmentReleasesTarget) {
    secure_buffer<int> a(4);
    a[0] = 10;
    secure_buffer<int> b(2);
    b[0] = 20;
    b = std::move(a);
    EXPECT_EQ(b[0], 10);
    EXPECT_EQ(b.size(), 4);
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(a.data(), nullptr);
}

TEST(SecureBufferTest, AllocZeroCount) {
    secure_buffer<int> buf(0);
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0);
}

}  // namespace
}  // namespace ssm::v1

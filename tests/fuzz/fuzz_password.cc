// fuzz_password.cc — Fuzz password validation and user auth paths
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "ssm/ssm.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2)
        return 0;

    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK)
        return 0;

    // Split input into password segments
    size_t pos = 0;

    auto consume_segment = [&]() -> std::vector<char> {
        if (pos >= size)
            return {};
        if (pos + 1 > size)
            return {};
        uint8_t len = data[pos++];
        size_t avail = size - pos;
        if (len > avail)
            len = static_cast<uint8_t>(avail);
        std::vector<char> seg(len + 1);
        if (len > 0)
            std::memcpy(seg.data(), data + pos, len);
        seg[len] = '\0';
        pos += len;
        return seg;
    };

    // Consume up to 4 segments for different test scenarios
    auto pw1 = consume_segment();
    auto pw2 = consume_segment();
    auto pw3 = consume_segment();
    auto pw4 = consume_segment();

    // Register user with fuzzed password
    if (!pw1.empty() && !pw2.empty()) {
        ssm_user_register(h, pw1.data(), pw2.data());
    }

    // Authenticate with fuzzed credentials
    if (!pw1.empty() && !pw2.empty()) {
        int valid = 0;
        ssm_user_authenticate(h, pw1.data(), pw2.data(), &valid);
    }

    // Change password with fuzzed values
    if (pw1.size() > 1 && pw2.size() > 1 && pw3.size() > 1) {
        ssm_user_change_password(h, pw1.data(), pw2.data(), pw3.data());
    }

    // Register second user and authenticate/interleave
    if (!pw3.empty() && !pw4.empty()) {
        ssm_user_register(h, pw3.data(), pw4.data());
    }

    // Delete user
    if (!pw1.empty() && !pw2.empty()) {
        ssm_user_delete(h, pw1.data(), pw2.data());
    }

    ssm_destroy(h);
    return 0;
}

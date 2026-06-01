#include "ssm/ssm.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4)
        return 0;

    ssm_handle* h = nullptr;
    if (ssm_init(&h, ":memory:", nullptr, 0) != SSM_OK)
        return 0;

    uint8_t op = data[0];
    size_t pos = 1;

    auto consume_str = [&]() -> std::vector<char> {
        if (pos >= size)
            return {};
        uint8_t len = data[pos++];
        if (pos + len > size || pos + len < pos)
            len = static_cast<uint8_t>(size - pos);
        std::vector<char> s(len + 1);
        std::memcpy(s.data(), data + pos, len);
        s[len] = '\0';
        pos += len;
        return s;
    };

    switch (op % 8) {
    case 0: {
        auto user = consume_str();
        auto pass = consume_str();
        if (!user.empty() && !pass.empty())
            ssm_user_register(h, user.data(), pass.data());
        break;
    }
    case 1: {
        auto user = consume_str();
        auto pass = consume_str();
        if (!user.empty() && !pass.empty()) {
            int valid = 0;
            ssm_user_authenticate(h, user.data(), pass.data(), &valid);
        }
        break;
    }
    case 2: {
        auto user = consume_str();
        auto pass = consume_str();
        if (!user.empty() && !pass.empty())
            ssm_user_delete(h, user.data(), pass.data());
        break;
    }
    case 3: {
        auto user = consume_str();
        auto old_pw = consume_str();
        auto new_pw = consume_str();
        if (!user.empty() && !old_pw.empty() && !new_pw.empty())
            ssm_user_change_password(h, user.data(), old_pw.data(), new_pw.data());
        break;
    }
    case 4: {
        auto user = consume_str();
        auto name = consume_str();
        if (!user.empty() && !name.empty()) {
            size_t key_len = size - pos;
            if (key_len > 0)
                ssm_secret_store(h, user.data(), data + pos, key_len, nullptr, 0,
                                 name.data(), nullptr);
        }
        break;
    }
    case 5: {
        auto user = consume_str();
        auto name = consume_str();
        if (!user.empty() && !name.empty()) {
            unsigned char buf[512];
            size_t len = sizeof(buf);
            ssm_secret_get(h, user.data(), name.data(), buf, &len, nullptr, nullptr);
        }
        break;
    }
    case 6: {
        auto user = consume_str();
        auto name = consume_str();
        if (!user.empty() && !name.empty())
            ssm_secret_delete(h, user.data(), name.data());
        break;
    }
    case 7: {
        auto user = consume_str();
        if (!user.empty())
            ssm_kek_rotate(h, user.data());
        break;
    }
    }

    ssm_destroy(h);
    return 0;
}

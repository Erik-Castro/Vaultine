#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

inline int hex_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

inline bool hex_decode(const char* hex, unsigned char* out, size_t* out_len,
                       size_t max_out = 32) {
    size_t len = std::strlen(hex);
    if (len % 2 != 0 || len == 0)
        return false;
    *out_len = len / 2;
    if (*out_len > max_out)
        return false;
    for (size_t i = 0; i < *out_len; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

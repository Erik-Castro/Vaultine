#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

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

inline bool hex_decode(const char* hex, size_t hex_len, std::vector<unsigned char>& out) {
    if (hex_len % 2 != 0 || hex_len == 0)
        return false;
    size_t out_len = hex_len / 2;
    out.resize(out_len);
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            out.clear();
            return false;
        }
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

inline std::string hex_encode(const unsigned char* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += hex[(data[i] >> 4) & 0xf];
        out += hex[data[i] & 0xf];
    }
    return out;
}

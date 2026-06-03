// fuzz_cli.cc — Fuzz CLI utility functions (hex_decode, argument parsing)
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "hex_utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2)
        return 0;

    // Fuzz hex_decode with various inputs
    // Copy input and ensure null termination for string functions
    std::vector<char> input(size + 1);
    std::memcpy(input.data(), data, size);
    input[size] = '\0';

    unsigned char out[32];
    size_t out_len = 0;
    hex_decode(input.data(), out, &out_len);

    // Fuzz hex_val with individual characters
    for (size_t i = 0; i < size; ++i)
        hex_val(static_cast<char>(data[i]));

    // Fuzz hex_decode with different max_out limits
    for (size_t limit = 1; limit <= 64; ++limit) {
        unsigned char buf[64];
        size_t blen = 0;
        hex_decode(input.data(), buf, &blen, limit);
    }

    return 0;
}

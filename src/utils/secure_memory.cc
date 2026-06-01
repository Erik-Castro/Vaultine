#include "utils/secure_memory.h"

#include <cstdlib>
#include <sys/mman.h>

#include <sodium.h>

namespace ssm::v1 {

void secure_erase(void* ptr, size_t len) noexcept {
    if (ptr && len > 0)
        sodium_memzero(ptr, len);
}

void* secure_alloc(size_t size) noexcept {
    if (size == 0)
        return nullptr;
    void* ptr = std::calloc(1, size);
    if (!ptr)
        return nullptr;
    if (mlock(ptr, size) != 0) {
        std::free(ptr);
        return nullptr;
    }
    return ptr;
}

void secure_free(void* ptr, size_t size) noexcept {
    if (ptr && size > 0) {
        munlock(ptr, size);
        std::free(ptr);
    }
}

}  // namespace ssm::v1

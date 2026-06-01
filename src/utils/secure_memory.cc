#include "utils/secure_memory.h"

#include <sodium.h>

namespace ssm::v1 {

void secure_erase(void* ptr, size_t len) noexcept
{
    if (ptr && len > 0)
        sodium_memzero(ptr, len);
}

} // namespace ssm::v1

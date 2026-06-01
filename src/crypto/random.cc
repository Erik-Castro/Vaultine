#include "crypto/random.h"

#include <sodium.h>

namespace ssm::v1 {

void random_bytes(unsigned char* buf, size_t len)
{
    randombytes_buf(buf, len);
}

} // namespace ssm::v1

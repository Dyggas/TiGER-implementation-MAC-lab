#pragma once
#include <cstddef>
#include <cstdint>

namespace tiger {

void shake256_hash(const uint8_t *in, std::size_t in_len,
                   uint8_t *out, std::size_t out_len);

void sha256_hash(const uint8_t *in, std::size_t in_len,
                    uint8_t out[32]);
} // namespace tiger

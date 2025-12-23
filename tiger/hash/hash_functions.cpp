#pragma once
#include "hash_functions.hpp"
#include "compact_fips202.cpp"

namespace tiger {

void shake256_hash(const uint8_t *in, std::size_t in_len,
                   uint8_t *out, std::size_t out_len) {
    FIPS202_SHAKE256(in, static_cast<unsigned int>(in_len), out, static_cast<int>(out_len));
}

void sha256_hash(const uint8_t *in, std::size_t in_len,
                    uint8_t *out) {
    FIPS202_SHA3_256(in, static_cast<unsigned int>(in_len), out);
}

} // namespace tiger

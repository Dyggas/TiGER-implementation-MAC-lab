#pragma once
#include "../core/polynomial.hpp"
#include "../core/params.hpp"
#include <cstdint>
#include <cstring>
#include <array>

namespace tiger {

// Public Key: [Seed_a (32 bytes)] [b compressed to log2(p) bits per coeff]

template<std::size_t N>
void pack_public_key(const std::array<uint8_t, 32>& seed_a,
                     const Polynomial<N>& b,
                     const TiGERParams& params,
                     uint8_t* out) {
    std::memcpy(out, seed_a.data(), 32);
    b.compress(out + 32, log2_pow2(params.p));
}

template<std::size_t N>
void unpack_public_key(const uint8_t* in,
                       const TiGERParams& params,
                       std::array<uint8_t, 32>& seed_a,
                       Polynomial<N>& b) {
    std::memcpy(seed_a.data(), in, 32);
    b.decompress(in + 32, log2_pow2(params.p));
}

// Secret Key: [s (N bytes)] [u (u_size)]

template<std::size_t N>
void pack_secret_key(const Polynomial<N>& s,
                     const uint8_t* u,
                     std::size_t u_size,
                     uint8_t* out) {
    s.serialize(out);
    std::memcpy(out + N, u, u_size);
}

template<std::size_t N>
void unpack_secret_key(const uint8_t* in,
                       std::size_t u_size,
                       Polynomial<N>& s,
                       uint8_t* u) {
    s.deserialize(in);
    std::memcpy(u, in + N, u_size);
}


// Ciphertext: [c1 compressed] [c2 compressed]

template<std::size_t N>
void pack_ciphertext(const Polynomial<N>& c1,
                     const Polynomial<N>& c2,
                     const TiGERParams& params,
                     uint8_t* out) {
    c1.compress(out, log2_pow2(params.k1));
    
    std::size_t c1_bytes = (N * log2_pow2(params.k1) + 7) / 8;
    c2.compress(out + c1_bytes, log2_pow2(params.k2));
}

template<std::size_t N>
void unpack_ciphertext(const uint8_t* in,
                       const TiGERParams& params,
                       Polynomial<N>& c1,
                       Polynomial<N>& c2) {
    c1.decompress(in, log2_pow2(params.k1));
    
    std::size_t c1_bytes = (N * log2_pow2(params.k1) + 7) / 8;
    c2.decompress(in + c1_bytes, log2_pow2(params.k2));
}

} // namespace tiger

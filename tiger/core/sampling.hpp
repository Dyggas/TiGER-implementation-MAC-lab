#pragma once

#include "params.cpp"
#include "polynomial.cpp"
#include "../hash/hash_functions.cpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <algorithm>

namespace tiger {


// Sample a sparse ternary polynomial with exact Hamming weight
template<std::size_t N>
Polynomial<N> sample_hwt(std::size_t hamming_weight, const uint8_t seed[32]);

// Sample a sparse ternary polynomial with exact Hamming weight, returning a SparseTernary vector
template<std::size_t N>
std::vector<SparseTernary> sample_hwt_sparse(std::size_t hamming_weight, 
                                              const uint8_t seed[32]);

// Generate a uniform random polynomial from a seed using SHAKE256
template<std::size_t N>
Polynomial<N> sample_uniform(const uint8_t seed[32]);

// Generate cryptographically secure random bytes
void random_bytes(uint8_t *out, std::size_t len);

// Generate random bytes into a fixed-size array
template<std::size_t N>
void random_bytes(std::array<uint8_t, N> &out);

// Expand a seed into arbitrary-length randomness using SHAKE256
void expand_seed(const uint8_t *seed, std::size_t seed_len,
                 uint8_t *out, std::size_t out_len);

// Derive a new seed from an existing seed with a counter/nonce (w + Nonce)
void derive_seed(const uint8_t base_seed[32], uint32_t counter,
                 uint8_t derived_seed[32]);


// ----------- Implementation -----------


template<std::size_t N>
std::vector<SparseTernary> sample_hwt_sparse(std::size_t hamming_weight,
                                              const uint8_t seed[32]) {
    // Step 1: Expand seed to get enough random bytes
    // Need: 2 bytes per position selection (Fisher-Yates)
    //       + 1 bit per sign (but we'll use 1 byte for simplicity)
    std::size_t needed_bytes = hamming_weight * 3; // conservative
    std::vector<uint8_t> random_stream(needed_bytes);
    shake256_hash(seed, 32, random_stream.data(), needed_bytes);
    
    // Step 2: Fisher-Yates shuffle to select hamming_weight unique positions
    std::vector<std::size_t> positions(N);
    for (std::size_t i = 0; i < N; ++i) {
        positions[i] = i;
    }
    
    std::size_t byte_idx = 0;
    for (std::size_t i = 0; i < hamming_weight; ++i) {
        // Get random index in range [i, N-1]
        // Use 2 bytes to avoid modulo bias for N=1024
        uint16_t rand_val = (static_cast<uint16_t>(random_stream[byte_idx]) << 8) |
                            static_cast<uint16_t>(random_stream[byte_idx + 1]);
        byte_idx += 2;
        
        std::size_t j = i + (rand_val % (N - i));
        std::swap(positions[i], positions[j]);
    }
    
    // Step 3: Assign random signs to selected positions
    std::vector<SparseTernary> result;
    result.reserve(hamming_weight);
    
    for (std::size_t i = 0; i < hamming_weight; ++i) {
        uint8_t sign_byte = random_stream[byte_idx++];
        int8_t sign = (sign_byte & 1) ? 1 : -1;
        result.push_back({positions[i], sign});
    }
    
    return result;
}

template<std::size_t N>
Polynomial<N> sample_hwt(std::size_t hamming_weight, const uint8_t seed[32]) {
    auto sparse = sample_hwt_sparse<N>(hamming_weight, seed);
    
    Polynomial<N> result;
    result.from_sparse(sparse);
    
    return result;
}

template<std::size_t N>
Polynomial<N> sample_uniform(const uint8_t seed[32]) {
    Polynomial<N> result;
    
    // Expand seed to N bytes using SHAKE256
    shake256_hash(seed, 32, result.data(), N);
    
    return result;
}

template<std::size_t N>
void random_bytes(std::array<uint8_t, N> &out) {
    random_bytes(out.data(), N);
}

} // namespace tiger

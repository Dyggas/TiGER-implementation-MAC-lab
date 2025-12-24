#pragma once
#include <cstddef>
#include <cstdint>

namespace tiger {

// Constants

// Always uses q = 256
inline constexpr unsigned TIGER_Q = 256;

// Dimension values 
inline constexpr std::size_t TIGER_N_128 = 512;
inline constexpr std::size_t TIGER_N_192 = 1024;
inline constexpr std::size_t TIGER_N_256 = 1024;

// Security Levels

enum class SecurityLevel {
    TIGER128,
    TIGER192,
    TIGER256
};

// Parameter Set Structure

//  TiGER parameter set for a specific security level
//
//  All parameters follow the TiGER specification:
//  - n: polynomial degree (512 or 1024)
//  - q: RLWE modulus (always 256)
//  - p: RLWR modulus for public key (64 or 128)
//  - k1, k2: compression moduli for ciphertext components
//  - hs: Hamming weight of secret key s
//  - hr: Hamming weight of ephemeral secret r
//  - he: Hamming weight of error terms e1, e2
//  - d: message length in bits (128, 192, or 256)
//  - f: error correction capacity for XEf (3 or 5 bits)
//  - u_size: size of u for Fujisaki-Okamoto transform
//  - pk_bytes, sk_bytes, ct_bytes: sizes in bytes of public key, secret key, ciphertext
struct TiGERParams {
    std::size_t n;      // Dimension (512 or 1024)
    unsigned    q;      // RLWE modulus (256)
    unsigned    p;      // RLWR modulus (64 or 128)
    unsigned    k1;     // c1 compression modulus
    unsigned    k2;     // c2 compression modulus
    std::size_t hs;     // Hamming weight of secret s
    std::size_t hr;     // Hamming weight of ephemeral r
    std::size_t he;     // Hamming weight of errors e1, e2
    std::size_t d;      // Message length in bits
    unsigned    f;      // Error correction capacity for XEf (bits)
    unsigned    u_size; // Size of u in secret key

    SecurityLevel level;
    
    // Computed sizes (in bytes) 
    std::size_t pk_bytes;  // Public key
    std::size_t sk_bytes;  // Secret key
    std::size_t ct_bytes;  // Ciphertext
    
    // Helper: shared secret size and seed size
    static constexpr std::size_t ss_bytes = 32;
    static constexpr std::size_t seed_bytes = 32;

    // Constructor
    constexpr TiGERParams(
        std::size_t n_,
        unsigned q_,
        unsigned p_,
        unsigned k1_,
        unsigned k2_,
        std::size_t hs_,
        std::size_t hr_,
        std::size_t he_,
        std::size_t d_,
        unsigned f_,
        unsigned u_size_,
        SecurityLevel level_,
        std::size_t pk_bytes_,
        std::size_t sk_bytes_,
        std::size_t ct_bytes_
    ) : n(n_), q(q_), p(p_), k1(k1_), k2(k2_),
        hs(hs_), hr(hr_), he(he_), d(d_), f(f_),
        u_size(u_size_), level(level_), pk_bytes(pk_bytes_),
        sk_bytes(sk_bytes_), ct_bytes(ct_bytes_) {}
};

// Predefined Parameter Sets

inline constexpr TiGERParams TIGER128_PARAMS(
    512, 256, 128, 128, 128, 
    160, 128, 32, 128, 3, 16,
    SecurityLevel::TIGER128, 
    480, 528, 1024 
);

inline constexpr TiGERParams TIGER192_PARAMS(
    1024, 256, 128, 128, 128,
    84, 84, 32, 256, 5, 32,
    SecurityLevel::TIGER192,
    928, 1056, 1792
);

inline constexpr TiGERParams TIGER256_PARAMS(
    1024, 256, 128, 128, 128,
    198, 198, 32, 256, 5, 32,
    SecurityLevel::TIGER256,
    928, 1056, 1792
);


// Functions

const TiGERParams& get_params(SecurityLevel level);

const char* get_level_name(SecurityLevel level);

// Compute public key size from parameters (verification)
// Formula: 32 (seed_a) + n * log2(p) bits
std::size_t compute_pk_bytes(const TiGERParams &params);

// Compute secret key size from parameters (verification)
// Formula: n (for s) + 32 (for u in IND-CCA)
std::size_t compute_sk_bytes(const TiGERParams &params);

// Compute ciphertext size from parameters (verification)
// Formula: n * log2(k1) + n * log2(k2) bits
std::size_t compute_ct_bytes(const TiGERParams &params);

// Validate parameter set against specification
bool validate_params(const TiGERParams &params);

// Print parameter set details to stdout
void print_params(const TiGERParams &params);


//  Helper functions for bit manipulation

//  Compute log2 of power-of-2 value
inline constexpr unsigned log2_pow2(unsigned x) {
    unsigned result = 0;
    while (x > 1) {
        x >>= 1;
        ++result;
    }
    return result;
}


// Check if value is power of 2
inline constexpr bool is_power_of_2(unsigned x) {
    return x != 0 && (x & (x - 1)) == 0;
}

} // namespace tiger

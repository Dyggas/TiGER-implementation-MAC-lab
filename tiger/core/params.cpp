#include "params.hpp"
#include <stdexcept>
#include <iostream>
#include <iomanip>

namespace tiger {

// Get parameter set by level

const TiGERParams& get_params(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::TIGER128:
            return TIGER128_PARAMS;
        case SecurityLevel::TIGER192:
            return TIGER192_PARAMS;
        case SecurityLevel::TIGER256:
            return TIGER256_PARAMS;
        default:
            throw std::invalid_argument("Invalid security level");
    }
}

// Get level name

const char* get_level_name(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::TIGER128: return "TiGER128";
        case SecurityLevel::TIGER192: return "TiGER192";
        case SecurityLevel::TIGER256: return "TiGER256";
        default: return "Unknown";
    }
}

// Size computation functions

std::size_t compute_pk_bytes(const TiGERParams &params) {
    // Public key = Seed_a (32 bytes) + b
    // b has n coefficients, each in Z_p, so n * log2(p) bits
    
    std::size_t seed_a_bytes = 32;
    unsigned log_p = log2_pow2(params.p);
    std::size_t b_bits = params.n * log_p;
    std::size_t b_bytes = (b_bits + 7) / 8;  // round up
    
    return seed_a_bytes + b_bytes;
}

std::size_t compute_sk_bytes(const TiGERParams &params) {
    // Secret key = s || u
    // Full storage: n bytes for s + u_size bytes for u
    
    return params.n + params.u_size;
}

std::size_t compute_ct_bytes(const TiGERParams &params) {
    // Ciphertext = c1 + c2
    // c1: n coefficients, each log2(k1) bits
    // c2: n coefficients, each log2(k2) bits
    
    unsigned log_k1 = log2_pow2(params.k1);
    unsigned log_k2 = log2_pow2(params.k2);
    
    std::size_t c1_bits = params.n * log_k1;
    std::size_t c2_bits = params.n * log_k2;
    
    return (c1_bits + c2_bits + 7) / 8;
}

// Validation

bool validate_params(const TiGERParams &params) {
    // Check basic constraints
    if (params.q != 256) {
        std::cerr << "Error: q must be 256\n";
        return false;
    }
    
    if (!is_power_of_2(params.p) || !is_power_of_2(params.k1) || !is_power_of_2(params.k2)) {
        std::cerr << "Error: p, k1, k2 must be powers of 2\n";
        return false;
    }
    
    if (params.n != 512 && params.n != 1024) {
        std::cerr << "Error: n must be 512 or 1024\n";
        return false;
    }
    
    if (params.hs > params.n || params.hr > params.n || params.he > params.n) {
        std::cerr << "Error: Hamming weights exceed dimension\n";
        return false;
    }
    
    if (params.d != 128 && params.d != 192 && params.d != 256) {
        std::cerr << "Error: message length d must be 128, 192, or 256\n";
        return false;
    }
    
    if (params.f != 3 && params.f != 5) {
        std::cerr << "Error: error correction capacity f must be 3 or 5\n";
        return false;
    }
    
    // Validate computed sizes match specification
    std::size_t computed_pk = compute_pk_bytes(params);
    std::size_t computed_sk = compute_sk_bytes(params);
    std::size_t computed_ct = compute_ct_bytes(params);
    
    if (computed_pk != params.pk_bytes) {
        std::cerr << "Error: pk_bytes mismatch. Expected " << params.pk_bytes
                  << ", computed " << computed_pk << "\n";
        return false;
    }
    
    if (computed_sk != params.sk_bytes) {
        std::cerr << "Error: sk_bytes mismatch. Expected " << params.sk_bytes
                  << ", computed " << computed_sk << "\n";
        return false;
    }
    
    if (computed_ct != params.ct_bytes) {
        std::cerr << "Error: ct_bytes mismatch. Expected " << params.ct_bytes
                  << ", computed " << computed_ct << "\n";
        return false;
    }
    
    return true;
}

// Print parameter details (I did not write allat but it's pretty)

void print_params(const TiGERParams &params) {
    std::cout << "┌─────────────────────────────────────────────────┐\n";
    std::cout << "│ " << std::setw(48) << std::left << get_level_name(params.level) << "│\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    
    std::cout << "│ Security Level: ";
    switch (params.level) {
        case SecurityLevel::TIGER128: std::cout << "NIST Level 1 (AES128)"; break;
        case SecurityLevel::TIGER192: std::cout << "NIST Level 3 (AES192)"; break;
        case SecurityLevel::TIGER256: std::cout << "NIST Level 5 (AES256)"; break;
    }
    std::cout << std::setw(48 - 16 - 21) << "" << "│\n";
    
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│ Core Parameters                                 │\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│   n (dimension):              " << std::setw(18) << std::right << params.n << "│\n";
    std::cout << "│   q (RLWE modulus):           " << std::setw(18) << params.q << "│\n";
    std::cout << "│   p (RLWR modulus):           " << std::setw(18) << params.p << "│\n";
    std::cout << "│   k1 (c1 compression):        " << std::setw(18) << params.k1 << "│\n";
    std::cout << "│   k2 (c2 compression):        " << std::setw(18) << params.k2 << "│\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│ Hamming Weights                                 │\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│   hs (secret):                " << std::setw(18) << params.hs << "│\n";
    std::cout << "│   hr (ephemeral):             " << std::setw(18) << params.hr << "│\n";
    std::cout << "│   he (error):                 " << std::setw(18) << params.he << "│\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│ Error Correction                                │\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│   d (message bits):           " << std::setw(18) << params.d << "│\n";
    std::cout << "│   f (ECC capacity):           " << std::setw(18) << params.f << "│\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│ Sizes (bytes)                                   │\n";
    std::cout << "├─────────────────────────────────────────────────┤\n";
    std::cout << "│   Public key:                 " << std::setw(18) << params.pk_bytes << "│\n";
    std::cout << "│   Secret key:                 " << std::setw(18) << params.sk_bytes << "│\n";
    std::cout << "│   Ciphertext:                 " << std::setw(18) << params.ct_bytes << "│\n";
    std::cout << "│   Shared secret:              " << std::setw(18) << TiGERParams::ss_bytes << "│\n";
    std::cout << "└─────────────────────────────────────────────────┘\n";
}

} // namespace tiger

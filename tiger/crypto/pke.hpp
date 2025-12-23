#pragma once
#include "../core/polynomial.cpp"
#include "../core/params.cpp"
#include "../core/sampling.cpp"
#include "../ecc/d2.cpp"
#include "../ecc/xef.cpp"
#include "../hash/hash_functions.cpp"
#include <array>
#include <cstdint>
#include <vector>

namespace tiger {

// PKE Public/Secret Key Structures

template<std::size_t N>
struct PKEPublicKey {
    std::array<uint8_t, 32> seed_a;  // Seed for polynomial a
    Polynomial<N>           b;       // b = round((p/q) · a*s)
};

template<std::size_t N>
struct PKESecretKey {
    Polynomial<N> s;  // Secret polynomial (sparse ternary)
};

// IND-CPA PKE

// KeyGen
// pk = (Seed_a || b), sk = s
template<std::size_t N>
void pke_keygen(const TiGERParams& params,
                PKEPublicKey<N>& pk,
                PKESecretKey<N>& sk);


// Encryption
// c = (c1 || c2)
template<std::size_t N>
void pke_encrypt(const TiGERParams& params,
                 const PKEPublicKey<N>& pk,
                 const uint8_t* msg,     // d bits
                 const uint8_t coin[32], // random w
                 std::vector<uint8_t>& ct);  // serialized (c1 || c2)

// Decryption
template<std::size_t N>
bool pke_decrypt(const TiGERParams& params,
                 const PKESecretKey<N>& sk,
                 const uint8_t* ct,      // serialized ciphertext
                 uint8_t* msg);          // recovered message (d bits)

} // namespace tiger

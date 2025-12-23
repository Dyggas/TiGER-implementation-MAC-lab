#pragma once
#include "../core/params.hpp"
#include "pke.hpp"
#include "../hash/hash_functions.hpp"
#include <array>
#include <vector>
#include <cstdint>

namespace tiger {


// KEM.KeyGen
// Generates IND-CCA keypair
void kem_keygen(const TiGERParams& params,
                std::vector<uint8_t>& pk, 
                std::vector<uint8_t>& sk);


// KEM.Encaps
// Generates ciphertext + shared secret
void kem_encaps(const TiGERParams& params,
                const std::vector<uint8_t>& pk,  // serialized public key
                std::vector<uint8_t>& ct,        // output serialized ciphertext
                std::array<uint8_t, 32>& ss);    // 256-bit shared secret


// KEM.Decaps
// Recovers shared secret from ciphertext
void kem_decaps(const TiGERParams& params,
                const std::vector<uint8_t>& pk,  // serialized public key
                const std::vector<uint8_t>& sk,  // serialized secret key
                const std::vector<uint8_t>& ct,  // serialized ciphertext
                std::array<uint8_t, 32>& ss);    // recovered shared secret

} // namespace tiger

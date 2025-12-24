#pragma once
#include "kem.hpp"
#include "pke.cpp"
#include "compression.cpp"
#include <cstring>

namespace tiger {

// Constant-time equality check for byte arrays

bool constant_time_equal(const uint8_t* a, const uint8_t* b, std::size_t len) {
    uint8_t diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// IND-CCA-KEM.KeyGen

void kem_keygen(const TiGERParams& params,
                std::vector<uint8_t>& pk_out,
                std::vector<uint8_t>& sk_out) {
    if (params.n == 512) {
        PKEPublicKey<512> pke_pk;
        PKESecretKey<512> pke_sk;
        
        pke_keygen(params, pke_pk, pke_sk);
        
        std::array<uint8_t, 32> u;  // max 32 bytes
        random_bytes(u.data(), params.u_size);
        
        // Serialize pk = (Seed_a || b)
        pk_out.resize(params.pk_bytes);
        pack_public_key(pke_pk.seed_a, pke_pk.b, params, pk_out.data());
        
        // Serialize sk = (s || u)
        sk_out.resize(params.sk_bytes);
        pack_secret_key(pke_sk.s, u.data(), params.u_size, sk_out.data());
        
    } else {  // N = 1024
        PKEPublicKey<1024> pke_pk;
        PKESecretKey<1024> pke_sk;
        
        pke_keygen(params, pke_pk, pke_sk);
        
        std::array<uint8_t, 32> u;
        random_bytes(u.data(), params.u_size);
        
        pk_out.resize(params.pk_bytes);
        pack_public_key(pke_pk.seed_a, pke_pk.b, params, pk_out.data());
        
        sk_out.resize(params.sk_bytes);
        pack_secret_key(pke_sk.s, u.data(), params.u_size, sk_out.data());
    }
}

// IND-CCA-KEM.Encapsulation

void kem_encaps(const TiGERParams& params,
                const std::vector<uint8_t>& pk_serialized,
                std::vector<uint8_t>& ct_out,
                std::array<uint8_t, 32>& ss) {
    uint8_t delta[32];
    random_bytes(delta, params.d / 8);
    
    if (params.n == 512) {
        PKEPublicKey<512> pk;
        std::array<uint8_t, 32> seed_a;
        Polynomial<512> b;
        unpack_public_key(pk_serialized.data(), params, seed_a, b);
        pk.seed_a = seed_a;
        pk.b = b;
        
        uint8_t h_delta[32];
        sha256_hash(delta, params.d / 8, h_delta);
        
        std::vector<uint8_t> ct_serialized;
        pke_encrypt(params, pk, delta, h_delta, ct_serialized);
        
        // K 
        std::vector<uint8_t> g_input;
        g_input.insert(g_input.end(), ct_serialized.begin(), ct_serialized.end());
        g_input.insert(g_input.end(), delta, delta + params.d / 8);
        shake256_hash(g_input.data(), g_input.size(), ss.data(), 32);
        
        ct_out = std::move(ct_serialized);
        
    } else {  // N = 1024
        PKEPublicKey<1024> pk;
        std::array<uint8_t, 32> seed_a;
        Polynomial<1024> b;
        unpack_public_key(pk_serialized.data(), params, seed_a, b);
        pk.seed_a = seed_a;
        pk.b = b;
        
        uint8_t h_delta[32];
        sha256_hash(delta, params.d / 8, h_delta);
        
        std::vector<uint8_t> ct_serialized;
        pke_encrypt(params, pk, delta, h_delta, ct_serialized);
        
        std::vector<uint8_t> g_input;
        g_input.insert(g_input.end(), ct_serialized.begin(), ct_serialized.end());
        g_input.insert(g_input.end(), delta, delta + params.d / 8);
        shake256_hash(g_input.data(), g_input.size(), ss.data(), 32);
        
        ct_out = std::move(ct_serialized);
    }
}

// Decapsulation

void kem_decaps(const TiGERParams& params,
                const std::vector<uint8_t>& pk_serialized,
                const std::vector<uint8_t>& sk_serialized,
                const std::vector<uint8_t>& ct_serialized,
                std::array<uint8_t, 32>& ss) {
    uint8_t u[32];
    
    if (params.n == 512) {
        PKESecretKey<512> sk;
        Polynomial<512> s;
        unpack_secret_key(sk_serialized.data(), params.u_size, s, u);
        sk.s = s;
        
        PKEPublicKey<512> pk;
        std::array<uint8_t, 32> seed_a;
        Polynomial<512> b;
        unpack_public_key(pk_serialized.data(), params, seed_a, b);
        pk.seed_a = seed_a;
        pk.b = b;
        
        uint8_t delta_hat[32];
        pke_decrypt(params, sk, ct_serialized.data(), delta_hat);
        
        uint8_t h_delta_hat[32];
        sha256_hash(delta_hat, params.d / 8, h_delta_hat);
        
        std::vector<uint8_t> ct_recomputed;
        pke_encrypt(params, pk, delta_hat, h_delta_hat, ct_recomputed);
        
        bool ct_match = ct_serialized.size() == ct_recomputed.size() &&
                       constant_time_equal(ct_serialized.data(), ct_recomputed.data(), 
                                         ct_serialized.size());
        
        // Select: if match then shake256_hash(c, delta_hat) else shake256_hash(c, u)
        std::vector<uint8_t> g_input;
        g_input.insert(g_input.end(), ct_serialized.begin(), ct_serialized.end());
        
        if (ct_match) {
            g_input.insert(g_input.end(), delta_hat, delta_hat + params.d / 8);
        } else {
            g_input.insert(g_input.end(), u, u + params.u_size);
        }
        
        shake256_hash(g_input.data(), g_input.size(), ss.data(), 32);
        
    } else {  // N = 1024
        PKESecretKey<1024> sk;
        Polynomial<1024> s;
        unpack_secret_key(sk_serialized.data(), params.u_size, s, u);
        sk.s = s;
        
        PKEPublicKey<1024> pk;
        std::array<uint8_t, 32> seed_a;
        Polynomial<1024> b;
        unpack_public_key(pk_serialized.data(), params, seed_a, b);
        pk.seed_a = seed_a;
        pk.b = b;
        
        uint8_t delta_hat[32];
        pke_decrypt(params, sk, ct_serialized.data(), delta_hat);
        
        uint8_t h_delta_hat[32];
        sha256_hash(delta_hat, params.d / 8, h_delta_hat);
        
        std::vector<uint8_t> ct_recomputed;
        pke_encrypt(params, pk, delta_hat, h_delta_hat, ct_recomputed);
        
        bool ct_match = ct_serialized.size() == ct_recomputed.size() &&
                       constant_time_equal(ct_serialized.data(), ct_recomputed.data(), 
                                         ct_serialized.size());
        
        std::vector<uint8_t> g_input;
        g_input.insert(g_input.end(), ct_serialized.begin(), ct_serialized.end());
        
        if (ct_match) {
            g_input.insert(g_input.end(), delta_hat, delta_hat + params.d / 8);
        } else {
            g_input.insert(g_input.end(), u, u + params.u_size);
        }
        
        shake256_hash(g_input.data(), g_input.size(), ss.data(), 32);
    }
}

} // namespace tiger

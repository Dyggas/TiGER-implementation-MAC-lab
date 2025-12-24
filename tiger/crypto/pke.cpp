#pragma once
#include "pke.hpp"
#include "compression.hpp"
#include <cstring>

namespace tiger {

// KeyGen 

template<std::size_t N>
void pke_keygen(const TiGERParams& params,
                PKEPublicKey<N>& pk,
                PKESecretKey<N>& sk) {
    uint8_t seed_a[32], seed_s[32];
    random_bytes(seed_a, 32);
    random_bytes(seed_s, 32);
    
    // 3: a <- SHAKE256(Seed_a, n/8)
    Polynomial<N> a = sample_uniform<N>(seed_a);
    
    // 4: s <- HWT_n(hs, Seed_s)
    sk.s = sample_hwt<N>(params.hs, seed_s);
    
    // 5: b <- round((p/q) · a*s)
    auto a_times_s = a.multiply_sparse(sk.s.to_sparse());  // sparse mult
    pk.b = a_times_s.scale_round(params.p, params.q);
    
    // Store seed_a in pk
    std::memcpy(pk.seed_a.data(), seed_a, 32);
}

// Encryption

template<std::size_t N>
void pke_encrypt(const TiGERParams& params,
                 const PKEPublicKey<N>& pk,
                 const uint8_t* msg, 
                 const uint8_t coin[32],
                 std::vector<uint8_t>& ct) {
    uint8_t w[32];
    std::memcpy(w, coin, 32);
    
    // 1: r <- HWT_n(hr, w)
    Polynomial<N> r = sample_hwt<N>(params.hr, w);
    
    // 2-3: Seed_e1 <- (w + Nonce), Seed_e2 <- (w + Nonce + 1)
    uint8_t e1_seed[32], e2_seed[32];
    derive_seed(w, 0, e1_seed);
    derive_seed(w, 1, e2_seed);
    
    // 4: e1 <- HWT_n(he, Seed_e1), e2 <- HWT_n(he, Seed_e2)
    Polynomial<N> e1 = sample_hwt<N>(params.he, e1_seed);
    Polynomial<N> e2 = sample_hwt<N>(params.he, e2_seed);

    // 5: Parse pk
    Polynomial<N> a = sample_uniform<N>(pk.seed_a.data());
    
    // 6: c1 <- round((k1/q) · (a*r + e1))
    auto a_times_r = a.multiply_sparse(r.to_sparse());
    auto ar_plus_e1 = a_times_r + e1;
    // Polynomial<N> c1 = ar_plus_e1.scale_round(params.k1, params.q); 
    Polynomial<N> c1 = ar_plus_e1;
    
    // 7: c2 <- round((k2/q) · ((q/2)·eccENC(msg) + ((q/p)·b)*r + e2))
    // Step 7.1: eccENC(msg)
    std::vector<uint8_t> xef_codeword(params.d * 2 / 8);
    xef_encode(msg, params.d / 8, xef_codeword.data(), params.f);

    // Step 7.2: D2 encode to polynomial
    Polynomial<N> encoded_msg;
    d2_encode_bits_to_poly(xef_codeword.data(), params.d * 2, encoded_msg);
    
    // Step 7.3: Scale by q/2 - already done in d2 encoding
    // encoded_msg = encoded_msg.scale(params.q / 2);
    
    // Step 7.4: ((q/p)·b)*r
    auto scaled_br = pk.b.scale(params.q / params.p); 
    auto b_times_r = scaled_br.multiply_sparse(r.to_sparse());  


    
    
    // Step 7.5: Sum + e2
    auto sum = encoded_msg + b_times_r + e2;
    // Polynomial<N> c2 = sum.scale_round(params.k2, params.q);
    Polynomial<N> c2 = sum;

    // 8: Serialize ct = (c1 || c2)
    ct.resize(params.ct_bytes);
    pack_ciphertext(c1, c2, params, ct.data());
}

// Decryption

template<std::size_t N>
void pke_decrypt(const TiGERParams& params,
                 const PKESecretKey<N>& sk,
                 const uint8_t* ct_data,
                 uint8_t* msg) {
    // Parse ciphertext
    Polynomial<N> c1, c2;
    unpack_ciphertext(ct_data, params, c1, c2);
    
    // 1: Parse c = (c1 || c2)

    // 2: M' <- round((2/q) · ((q/k2)·c2 − ((q/k1)·c1)*s))
    // Polynomial<N> c1_full = c1.scale_round(params.q, params.k1);
    // Polynomial<N> c2_full = c2.scale_round(params.q, params.k2);

    Polynomial<N>& c1_full = c1;
    Polynomial<N>& c2_full = c2;
    
    Polynomial<N> c1s = c1_full.multiply_sparse(sk.s.to_sparse());
    Polynomial<N> diff = c2_full - c1s;
    
    // Nice scaling I have there. It would be a shame if I had already done it in d2 encoding.
    // A real shame. Would have lost me many hours. ...
    // Polynomial<N> recovered;
    // recovered = diff.scale_round(2, params.q);
    // THIS is the missing spec step: round((2/q)*diff)
    Polynomial<N> recovered = diff.scale_round(2, params.q);

    // Convert {0,1} -> {0,128} for your D2 decoder
    recovered = recovered.scale(params.q / 2);
    
    // 3: M <- eccDEC(M')
    std::vector<uint8_t> xef_codeword(params.d * 2 / 8);
    d2_decode_poly_to_bits(diff, xef_codeword.data(), params.d * 2);
    
    xef_decode(xef_codeword.data(), params.d / 8, msg, params.f);
}

// Explicit template instantiations

template void pke_keygen<512>(const TiGERParams&, PKEPublicKey<512>&, PKESecretKey<512>&);
template void pke_keygen<1024>(const TiGERParams&, PKEPublicKey<1024>&, PKESecretKey<1024>&);

template void pke_encrypt<512>(const TiGERParams&, const PKEPublicKey<512>&, 
                               const uint8_t*, const uint8_t[32], std::vector<uint8_t>&);
template void pke_encrypt<1024>(const TiGERParams&, const PKEPublicKey<1024>&, 
                                const uint8_t*, const uint8_t[32], std::vector<uint8_t>&);

template void pke_decrypt<512>(const TiGERParams&, const PKESecretKey<512>&, 
                               const uint8_t*, uint8_t*);
template void pke_decrypt<1024>(const TiGERParams&, const PKESecretKey<1024>&, 
                                const uint8_t*, uint8_t*);

} // namespace tiger

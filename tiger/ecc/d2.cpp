#pragma once
#include "d2.hpp"

namespace tiger {

void d2_encode_bits_to_poly(const uint8_t* bits, size_t num_bits, 
                           Polynomial<512>& poly) {
    
    for (size_t i = 0; i < 512; ++i) {
        poly[i] = 0;
    }

    if (num_bits * 2 > 512) {
        std::cerr << "D2 overflow: need " << (num_bits * 2) << " coeffs\n";
        return;
    }

    for (size_t i = 0; i < num_bits; i++) {
        uint8_t byte_idx = i / 8;
        uint8_t bit_idx = i % 8;
        uint8_t bit = (bits[byte_idx] >> bit_idx) & 1;
        
        uint8_t value = bit ? 128 : 0;
        
        poly[2 * i] = value;
        poly[2 * i + 1] = value;
    }
}

void d2_encode_bits_to_poly(const uint8_t* bits, size_t num_bits, 
                           Polynomial<1024>& poly) {
    
    for (size_t i = 0; i < 1024; ++i) {
        poly[i] = 0;
    }

    if (num_bits * 2 > 1024) {
        std::cerr << "D2 overflow: need " << (num_bits * 2) << " coeffs\n";
        return;
    }

    for (size_t i = 0; i < num_bits; i++) {
        uint8_t byte_idx = i / 8;
        uint8_t bit_idx = i % 8;
        uint8_t bit = (bits[byte_idx] >> bit_idx) & 1;
        
        uint8_t value = bit ? 128 : 0;
        
        poly[2 * i] = value;
        poly[2 * i + 1] = value;
    }
}


void d2_decode_poly_to_bits(const Polynomial<512>& poly, 
                           uint8_t* bits, size_t num_bits) {
    size_t bytes_needed = (num_bits + 7) / 8;
    for (size_t i = 0; i < bytes_needed; i++) bits[i] = 0;
    
    // Decode pairs: average duplicated bits
    for (size_t i = 0; i < num_bits; i++) {
        uint8_t c1 = poly[2 * i];
        uint8_t c2 = poly[2 * i + 1];
        
        // Average: if sum >= 128, bit=1
        uint16_t sum = static_cast<uint16_t>(c1) + static_cast<uint16_t>(c2);
        uint8_t bit = ((sum) >= 128) ? 1 : 0;
        
        bits[i / 8] |= (bit << (i % 8));
    }
}


void d2_decode_poly_to_bits(const Polynomial<1024>& poly, 
                           uint8_t* bits, size_t num_bits) {
    size_t bytes_needed = (num_bits + 7) / 8;
    for (size_t i = 0; i < bytes_needed; i++) bits[i] = 0;
    
    // Decode pairs: average duplicated bits
    for (size_t i = 0; i < num_bits; i++) {
        uint8_t c1 = poly[2 * i];
        uint8_t c2 = poly[2 * i + 1];
        
        // Average: if sum >= 128, bit=1
        uint16_t sum = static_cast<uint16_t>(c1) + static_cast<uint16_t>(c2);
        uint8_t bit = ((sum) >= 128) ? 1 : 0;
        
        bits[i / 8] |= (bit << (i % 8));
    }
}

} // tiger

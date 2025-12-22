#pragma once
#include "d2.hpp"

namespace tiger {

void d2_encode_bits_to_poly(const uint8_t* bits, size_t num_bits, 
                           Polynomial<512>& poly) {
    
    for (size_t i = 0; i < num_bits; i++) {
        uint8_t byte = bits[i / 8];
        uint8_t bit = (byte >> (i % 8)) & 1;
        
        uint8_t value = bit ? 128 : 0;
        
        poly[2 * i] = value;
        poly[2 * i + 1] = value;
    }
}

void d2_encode_bits_to_poly(const uint8_t* bits, size_t num_bits, 
                           Polynomial<1024>& poly) {
    
    for (size_t i = 0; i < num_bits; i++) {
        uint8_t byte = bits[i / 8];
        uint8_t bit = (byte >> (i % 8)) & 1;
        
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
        uint8_t bit = ((c1 + c2) >= 128) ? 1 : 0;
        
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
        uint8_t bit = ((c1 + c2) >= 128) ? 1 : 0;
        
        bits[i / 8] |= (bit << (i % 8));
    }
}

} // tiger

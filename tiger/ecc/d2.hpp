#pragma once
#include "../core/polynomial.hpp"
#include <cstdint>

namespace tiger {

void d2_encode_bits_to_poly(const uint8_t* bits, size_t num_bits, 
                           Polynomial<512>& poly); 
void d2_encode_bits_to_poly(const uint8_t* bits, size_t num_bits, 
                           Polynomial<1024>& poly); 

void d2_decode_poly_to_bits(const Polynomial<512>& poly, 
                           uint8_t* bits, size_t num_bits); 
void d2_decode_poly_to_bits(const Polynomial<1024>& poly, 
                           uint8_t* bits, size_t num_bits);

} // tiger

#include "../crypto/compression.cpp"
#include "../ecc/xef.cpp"
#include "../ecc/d2.cpp"
#include "../core/polynomial.cpp"
#include <iostream>
#include <random>
#include <cstring>

namespace tiger {

// Test D2 encoding/decoding roundtrip
bool test_d2_roundtrip() {
    std::cout << "Testing D2 encoding/decoding roundtrip..." << std::endl;
    
    // Test with known pattern
    uint8_t original[32] = {0};
    for (int i = 0; i < 32; i++) {
        original[i] = i & 0xFF;
    }
    
    // Encode to polynomial
    Polynomial<1024> poly;
    d2_encode_bits_to_poly(original, 256, poly);  // 256 bits = 32 bytes
    
    // Decode back
    uint8_t recovered[32] = {0};
    d2_decode_poly_to_bits(poly, recovered, 256);
    
    // Compare
    bool success = (std::memcmp(original, recovered, 32) == 0);
    
    if (!success) {
        std::cout << "  Original:  ";
        for (int i = 0; i < 16; i++) printf("%02x", original[i]);
        std::cout << std::endl;
        std::cout << "  Recovered: ";
        for (int i = 0; i < 16; i++) printf("%02x", recovered[i]);
        std::cout << std::endl;
    }
    
    std::cout << "  D2 roundtrip: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test XEf encoding/decoding without errors
bool test_xef_roundtrip() {
    std::cout << "Testing XEf encoding/decoding (no errors)..." << std::endl;
    
    // Test message (16 bytes = 128 bits for TIGER128)
    uint8_t original[16] = {0};
    for (int i = 0; i < 16; i++) {
        original[i] = (i * 17) & 0xFF;  // Pattern: 0x00, 0x11, 0x22...
    }
    
    // Encode with XEf (buffer must be 2x size)
    uint8_t codeword[32] = {0};
    size_t total_bits = xef_encode(original, 16, codeword, 3);  // f=3
    
    std::cout << "  XEf output length: " << total_bits << " bits" << std::endl;
    
    // Decode (no bit flips)
    uint8_t recovered[16] = {0};
    bool decode_success = xef_decode(codeword, 16, recovered, 3);
    
    // Compare
    bool success = (std::memcmp(original, recovered, 16) == 0);
    
    if (!success) {
        std::cout << "  Original:  ";
        for (int i = 0; i < 16; i++) printf("%02x", original[i]);
        std::cout << std::endl;
        std::cout << "  Recovered: ";
        for (int i = 0; i < 16; i++) printf("%02x", recovered[i]);
        std::cout << std::endl;
    }
    
    std::cout << "  XEf roundtrip: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test XEf error correction capability
bool test_xef_error_correction() {
    std::cout << "Testing XEf error correction (f=3)..." << std::endl;
    
    uint8_t original[16];
    std::memset(original, 0xAA, 16);  // 10101010 pattern
    
    // Encode
    uint8_t codeword[32] = {0};
    xef_encode(original, 16, codeword, 3);
    
    // Flip exactly 3 bits in different bytes
    codeword[0] ^= 0x01;   // Flip bit 0
    codeword[5] ^= 0x10;   // Flip bit 4 of byte 5
    codeword[10] ^= 0x80;  // Flip bit 7 of byte 10
    
    std::cout << "  Flipped 3 bits in codeword" << std::endl;
    
    // Decode with error correction
    uint8_t recovered[16] = {0};
    bool decode_success = xef_decode(codeword, 16, recovered, 3);
    
    // Compare
    bool success = (std::memcmp(original, recovered, 16) == 0);
    
    if (!success) {
        std::cout << "  Original:  ";
        for (int i = 0; i < 16; i++) printf("%02x", original[i]);
        std::cout << std::endl;
        std::cout << "  Recovered: ";
        for (int i = 0; i < 16; i++) printf("%02x", recovered[i]);
        std::cout << std::endl;
    }
    
    std::cout << "  Error correction: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test combined D2 + XEf workflow (like in encryption)
bool test_d2_xef_combined() {
    std::cout << "Testing combined D2+XEf workflow..." << std::endl;
    
    // Original message
    uint8_t message[16];
    for (int i = 0; i < 16; i++) message[i] = i * 13;
    
    // Step 1: XEf encode
    uint8_t xef_codeword[32] = {0};
    xef_encode(message, 16, xef_codeword, 3);
    
    // Step 2: D2 encode to polynomial (256 bits)
    Polynomial<1024> poly;
    d2_encode_bits_to_poly(xef_codeword, 256, poly);
    
    // Simulate noise: add small random values
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> noise_dist(0, 10);
    for (size_t i = 0; i < 512; i++) {
        int val = static_cast<int>(poly[i]) + noise_dist(rng);
        poly[i] = static_cast<uint8_t>(val & 0xFF);
    }
    // for (size_t i = 0; i < 1024; i++) {
    //     if (i % 2 == 0) {
    //         poly[i] = 128;
    //     }
    // }
    // poly[0] = 128;
    // poly[1] = 128;
    
    // Step 3: D2 decode from polynomial
    uint8_t decoded_codeword[32] = {0};
    d2_decode_poly_to_bits(poly, decoded_codeword, 256);
    
    // Step 4: XEf decode
    uint8_t recovered_msg[16] = {0};
    xef_decode(decoded_codeword, 16, recovered_msg, 3);
    
    // Compare
    bool success = (std::memcmp(message, recovered_msg, 16) == 0);
    
    if (!success) {
        std::cout << "  Original:  ";
        for (int i = 0; i < 16; i++) printf("%02x", message[i]);
        std::cout << std::endl;
        std::cout << "  Recovered: ";
        for (int i = 0; i < 16; i++) printf("%02x", recovered_msg[i]);
        std::cout << std::endl;
    }
    
    std::cout << "  D2+XEf combined: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test D2 encoding properties
bool test_d2_duplication() {
    std::cout << "Testing D2 bit duplication..." << std::endl;
    
    // Single bit pattern
    uint8_t bits[1] = {0b10101010};
    Polynomial<1024> poly;
    d2_encode_bits_to_poly(bits, 8, poly);
    
    // Check that each bit is duplicated
    bool success = true;
    for (int i = 0; i < 8; i++) {
        uint8_t expected = ((bits[0] >> i) & 1) ? 128 : 0;
        if (poly[2*i] != expected || poly[2*i+1] != expected) {
            std::cout << "  Bit " << i << " not properly duplicated: "
                      << "poly[" << 2*i << "]=" << (int)poly[2*i]
                      << ", poly[" << 2*i+1 << "]=" << (int)poly[2*i+1]
                      << ", expected=" << (int)expected << std::endl;
            success = false;
        }
    }
    
    std::cout << "  D2 duplication: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test edge case: all zeros
bool test_all_zeros() {
    std::cout << "Testing all-zeros message..." << std::endl;
    
    uint8_t zeros[16] = {0};
    uint8_t codeword[32] = {0};
    uint8_t recovered[16];
    
    xef_encode(zeros, 16, codeword, 3);
    xef_decode(codeword, 16, recovered, 3);
    
    bool success = (std::memcmp(zeros, recovered, 16) == 0);
    std::cout << "  All-zeros: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test edge case: all ones
bool test_all_ones() {
    std::cout << "Testing all-ones message..." << std::endl;
    
    uint8_t ones[16];
    std::memset(ones, 0xFF, 16);
    uint8_t codeword[32] = {0};
    uint8_t recovered[16];
    
    xef_encode(ones, 16, codeword, 3);
    xef_decode(codeword, 16, recovered, 3);
    
    bool success = (std::memcmp(ones, recovered, 16) == 0);
    std::cout << "  All-ones: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Run all tests
void run_all_tests() {
    std::cout << "\n===== D2 + XEf Encoding Tests =====" << std::endl;
    
    int passed = 0, total = 0;
    
    #define RUN_TEST(test) do { \
        total++; \
        if (test()) passed++; \
        std::cout << std::endl; \
    } while(0)
    
    RUN_TEST(test_d2_duplication);
    RUN_TEST(test_d2_roundtrip);
    RUN_TEST(test_xef_roundtrip);
    RUN_TEST(test_xef_error_correction);
    RUN_TEST(test_d2_xef_combined);
    RUN_TEST(test_all_zeros);
    RUN_TEST(test_all_ones);
    
    std::cout << "===== Test Summary =====" << std::endl;
    std::cout << "Passed: " << passed << "/" << total << std::endl;
    
    if (passed == total) {
        std::cout << "✓ All tests passed!" << std::endl;
    } else {
        std::cout << "✗ Some tests failed" << std::endl;
    }
}

} // namespace tiger
int main() {
    tiger::run_all_tests();
    return 0;
}
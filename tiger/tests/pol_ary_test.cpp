#include "../core/polynomial.cpp"
#include "../core/params.cpp"
#include "../core/sampling.cpp"
#include <iostream>
#include <cstring>

namespace tiger {
namespace test {

// Test basic polynomial arithmetic
bool test_poly_addition() {
    std::cout << "Testing polynomial addition..." << std::endl;
    
    Polynomial<512> a, b;
    a[0] = 100; a[1] = 200;
    b[0] = 50;  b[1] = 100;
    
    auto c = a + b;
    
    bool success = (c[0] == 150 && c[1] == 44);  // 200+100=300, mod 256 = 44
    if (!success) {
        std::cout << "  Expected: c[0]=150, c[1]=44" << std::endl;
        std::cout << "  Got:      c[0]=" << (int)c[0] << ", c[1]=" << (int)c[1] << std::endl;
    }
    
    std::cout << "  Addition: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test polynomial subtraction
bool test_poly_subtraction() {
    std::cout << "Testing polynomial subtraction..." << std::endl;
    
    Polynomial<512> a, b;
    a[0] = 100; a[1] = 50;
    b[0] = 150; b[1] = 100;
    
    auto c = a - b;
    
    // 100-150 = -50 = 206 (mod 256)
    // 50-100 = -50 = 206 (mod 256)
    bool success = (c[0] == 206 && c[1] == 206);
    if (!success) {
        std::cout << "  Expected: c[0]=206, c[1]=206" << std::endl;
        std::cout << "  Got:      c[0]=" << (int)c[0] << ", c[1]=" << (int)c[1] << std::endl;
    }
    
    std::cout << "  Subtraction: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test scale operation (no rounding)
bool test_scale() {
    std::cout << "Testing scale operation..." << std::endl;
    
    Polynomial<512> a;
    a[0] = 64;   // 64 * 2 = 128
    a[1] = 200;  // 200 * 2 = 400, mod 256 = 144
    
    auto b = a.scale(2);
    
    bool success = (b[0] == 128 && b[1] == 144);
    if (!success) {
        std::cout << "  Expected: b[0]=128, b[1]=144" << std::endl;
        std::cout << "  Got:      b[0]=" << (int)b[0] << ", b[1]=" << (int)b[1] << std::endl;
    }
    
    std::cout << "  Scale: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test scale_round operation
bool test_scale_round() {
    std::cout << "Testing scale_round operation..." << std::endl;
    
    Polynomial<512> a;
    a[0] = 100;  // (100*2 + 128/2) / 128 = (200 + 64) / 128 = 264/128 = 2
    a[1] = 191;  // (191*2 + 64) / 128 = (382 + 64) / 128 = 446/128 = 3
    a[2] = 64;   // (64*2 + 64) / 128 = (128 + 64) / 128 = 192/128 = 1
    
    auto b = a.scale_round(2, 128);  // (2/128) with rounding
    
    bool success = (b[0] == 2 && b[1] == 3 && b[2] == 1);
    if (!success) {
        std::cout << "  Expected: b[0]=2, b[1]=3, b[2]=1" << std::endl;
        std::cout << "  Got:      b[0]=" << (int)b[0] 
                  << ", b[1]=" << (int)b[1] 
                  << ", b[2]=" << (int)b[2] << std::endl;
    }
    
    std::cout << "  Scale_round: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test sparse ternary multiplication
bool test_sparse_multiply() {
    std::cout << "Testing sparse ternary multiplication..." << std::endl;
    
    Polynomial<512> a;
    a[0] = 10;
    a[1] = 20;
    a[2] = 30;
    
    // Sparse: s[0] = 1, s[2] = -1
    std::vector<SparseTernary> s = {{0, 1}, {2, -1}};
    
    // Result: a[i]*1 at positions [0..511], a[i]*(-1) at positions [2..511,0,1]
    // r[0] = a[0]*1 + a[510]*(-1) (wrapped from 512-2)
    // r[1] = a[1]*1 + a[511]*(-1) (wrapped from 513-2)
    // r[2] = a[2]*1 + a[0]*(-1)
    auto r = a.multiply_sparse(s);
    
    // r[2] should be 30 - 10 = 20
    bool success = (r[2] == 20);
    if (!success) {
        std::cout << "  Expected: r[2]=20" << std::endl;
        std::cout << "  Got:      r[2]=" << (int)r[2] << std::endl;
    }
    
    std::cout << "  Sparse multiply: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test encryption step: a*r
bool test_encryption_step_ar() {
    std::cout << "Testing encryption step: a*r..." << std::endl;
    
    const auto& params = TIGER128_PARAMS;
    
    // Create simple test vectors
    uint8_t seed_a[32] = {0};
    uint8_t seed_r[32] = {1};
    
    Polynomial<512> a = sample_uniform<512>(seed_a);
    Polynomial<512> r = sample_hwt<512>(params.hr, seed_r);
    
    auto sparse_r = r.to_sparse();
    auto ar = a.multiply_sparse(sparse_r);
    
    // Check result is non-zero
    bool has_nonzero = false;
    for (size_t i = 0; i < 10; i++) {
        if (ar[i] != 0) {
            has_nonzero = true;
            break;
        }
    }
    
    std::cout << "  a*r produces non-zero: " << (has_nonzero ? "✓ PASS" : "✗ FAIL") << std::endl;
    return has_nonzero;
}

// Test key generation step: (p/q)*a*s
bool test_keygen_compression() {
    std::cout << "Testing KeyGen compression: (p/q)*a*s..." << std::endl;
    
    const auto& params = TIGER128_PARAMS;
    
    uint8_t seed_a[32] = {0};
    uint8_t seed_s[32] = {2};
    
    Polynomial<512> a = sample_uniform<512>(seed_a);
    Polynomial<512> s = sample_hwt<512>(params.hs, seed_s);
    
    auto sparse_s = s.to_sparse();
    auto as_product = a.multiply_sparse(sparse_s);
    
    // Compress: (p/q) * as = (128/256) * as = 0.5 * as
    auto b = as_product.scale_round(params.p, params.q);
    
    // Check that b is roughly half of as_product values
    bool reasonable = true;
    for (size_t i = 0; i < 10; i++) {
        if (as_product[i] != 0) {
            uint32_t expected = (as_product[i] * params.p + params.q/2) / params.q;
            if (b[i] != (expected & 0xFF)) {
                std::cout << "  Mismatch at i=" << i << ": as[i]=" << (int)as_product[i]
                          << ", b[i]=" << (int)b[i] << ", expected=" << expected << std::endl;
                reasonable = false;
            }
        }
    }
    
    std::cout << "  KeyGen compression: " << (reasonable ? "✓ PASS" : "✗ FAIL") << std::endl;
    return reasonable;
}

// Test decryption computation: c2 - c1*s
bool test_decryption_subtraction() {
    std::cout << "Testing decryption: c2 - c1*s..." << std::endl;
    
    Polynomial<512> c1, c2, s;
    c1[0] = 100; c1[1] = 50;
    c2[0] = 200; c2[1] = 150;
    s[0] = 1;    // Simple secret
    
    auto sparse_s = s.to_sparse();
    auto c1s = c1.multiply_sparse(sparse_s);
    auto diff = c2 - c1s;
    
    // c1s should equal c1 (since s[0]=1 and rest are 0)
    // diff should be c2 - c1
    bool success = (diff[0] == 100 && diff[1] == 100);
    if (!success) {
        std::cout << "  c1s[0]=" << (int)c1s[0] << ", c1s[1]=" << (int)c1s[1] << std::endl;
        std::cout << "  diff[0]=" << (int)diff[0] << ", diff[1]=" << (int)diff[1] << std::endl;
    }
    
    std::cout << "  Decryption subtraction: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test full encryption->decryption arithmetic path
bool test_full_arithmetic_path() {
    std::cout << "Testing full arithmetic path..." << std::endl;
    
    const auto& params = TIGER128_PARAMS;
    
    // Simulate encryption/decryption with simple values
    Polynomial<512> msg_poly;
    msg_poly[0] = 128;  // bit=1 encoded as 128
    msg_poly[1] = 128;
    msg_poly[2] = 0;    // bit=0
    msg_poly[3] = 0;
    
    // Scale by q/2 (128)
    auto scaled_msg = msg_poly.scale(params.q / 2);
    
    // Simulate small noise
    Polynomial<512> noise;
    noise[0] = 3;
    noise[1] = 253;  // -3 in mod 256
    
    auto c2_sim = scaled_msg + noise;
    
    // Decrypt: scale by 2/q
    auto recovered = c2_sim.scale_round(2, params.q);
    
    // Should recover 1, 1, 0, 0
    bool success = (recovered[0] >= 64 && recovered[1] >= 64 && 
                    recovered[2] < 64 && recovered[3] < 64);
    if (!success) {
        std::cout << "  recovered[0]=" << (int)recovered[0] 
                  << ", recovered[1]=" << (int)recovered[1]
                  << ", recovered[2]=" << (int)recovered[2]
                  << ", recovered[3]=" << (int)recovered[3] << std::endl;
    }
    
    std::cout << "  Full arithmetic: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test scale_round with TIGER parameters
bool test_tiger_scale_parameters() {
    std::cout << "Testing TIGER scale parameters..." << std::endl;
    
    const auto& params = TIGER128_PARAMS;
    
    Polynomial<512> a;
    a[0] = 128;  // Middle value
    a[1] = 64;   // Quarter
    a[2] = 192;  // Three quarters
    
    // Test (k1/q) scaling: 64/256 = 1/4
    auto b = a.scale_round(params.k1, params.q);
    std::cout << "  (k1/q) scaling: a[0]=128 -> b[0]=" << (int)b[0] 
              << " (expected ~32)" << std::endl;
    
    // Test (p/q) scaling: 128/256 = 1/2
    auto c = a.scale_round(params.p, params.q);
    std::cout << "  (p/q) scaling:  a[0]=128 -> c[0]=" << (int)c[0] 
              << " (expected ~64)" << std::endl;
    
    // Test (2/q) scaling: 2/256 = 1/128
    auto d = a.scale_round(2, params.q);
    std::cout << "  (2/q) scaling:  a[0]=128 -> d[0]=" << (int)d[0] 
              << " (expected ~1)" << std::endl;
    
    bool success = (b[0] == 32 && c[0] == 64 && d[0] == 1);
    std::cout << "  TIGER parameters: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

// Test inverse operations: expand then compress
bool test_expand_compress_inverse() {
    std::cout << "Testing expand/compress inverse..." << std::endl;
    
    const auto& params = TIGER128_PARAMS;
    
    Polynomial<512> original;
    original[0] = 32;
    original[1] = 16;
    
    // Compress with k1, then expand back
    auto compressed = original.scale_round(params.k1, params.q);
    auto expanded = compressed.scale_round(params.q, params.k1);
    
    std::cout << "  original[0]=" << (int)original[0] 
              << " -> compressed=" << (int)compressed[0]
              << " -> expanded=" << (int)expanded[0] << std::endl;
    
    // Won't be exact due to rounding, but should be close
    int diff0 = std::abs((int)expanded[0] - (int)original[0]);
    int diff1 = std::abs((int)expanded[1] - (int)original[1]);
    bool success = (diff0 <= 2 && diff1 <= 2);
    
    std::cout << "  Expand/compress: " << (success ? "✓ PASS" : "✗ FAIL") << std::endl;
    return success;
}

void run_arithmetic_tests() {
    std::cout << "\n===== Polynomial Arithmetic Tests =====" << std::endl;
    
    int passed = 0, total = 0;
    
    #define RUN_TEST(test) do { \
        total++; \
        if (test()) passed++; \
        std::cout << std::endl; \
    } while(0)
    
    RUN_TEST(test_poly_addition);
    RUN_TEST(test_poly_subtraction);
    RUN_TEST(test_scale);
    RUN_TEST(test_scale_round);
    RUN_TEST(test_sparse_multiply);
    RUN_TEST(test_encryption_step_ar);
    RUN_TEST(test_keygen_compression);
    RUN_TEST(test_decryption_subtraction);
    RUN_TEST(test_tiger_scale_parameters);
    RUN_TEST(test_expand_compress_inverse);
    RUN_TEST(test_full_arithmetic_path);
    
    std::cout << "===== Arithmetic Test Summary =====" << std::endl;
    std::cout << "Passed: " << passed << "/" << total << std::endl;
    
    if (passed == total) {
        std::cout << "✓ All arithmetic tests passed!" << std::endl;
    } else {
        std::cout << "✗ Some arithmetic tests failed" << std::endl;
    }
}

} // namespace test
} // namespace tiger

int main() {
    tiger::test::run_arithmetic_tests();
    return 0;
}
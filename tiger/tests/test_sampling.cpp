// test_sampling.cpp
#include <iostream>
#include <iomanip>
#include <map>
#include <cstring>
#include "../core/sampling.cpp"
#include "../core/params.cpp"

using namespace tiger;

void print_sparse(const std::vector<SparseTernary> &sparse, const char *label) {
    std::cout << label << " (" << sparse.size() << " terms):\n";
    std::size_t show = std::min<std::size_t>(sparse.size(), std::size_t(10)); // have to define type explicitly since <windows.h> defines min macro
    for (std::size_t i = 0; i < show; ++i) {
        std::cout << "  [" << sparse[i].index << "] = " 
                  << (sparse[i].sign > 0 ? "+1" : "-1") << "\n";
    }
    if (sparse.size() > show) {
        std::cout << "  ... (" << (sparse.size() - show) << " more)\n";
    }
}

void test_random_bytes() {
    std::cout << "\n=== Test: random_bytes ===\n";
    
    uint8_t buf1[32];
    uint8_t buf2[32];
    
    random_bytes(buf1, 32);
    random_bytes(buf2, 32);
    
    // Should be different
    bool different = std::memcmp(buf1, buf2, 32) != 0;
    std::cout << "Two random samples differ: " << (different ? "✓" : "✗") << "\n";
    
    std::cout << "Sample 1: ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) 
                  << int(buf1[i]);
    }
    std::cout << "...\n" << std::dec;

    std::cout << "Sample 2: ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) 
                  << int(buf2[i]);
    }
    std::cout << "...\n" << std::dec;
}

void test_expand_seed() {
    std::cout << "\n=== Test: expand_seed ===\n";
    
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = i;
    
    uint8_t out1[64];
    uint8_t out2[64];
    
    expand_seed(seed, 32, out1, 64);
    expand_seed(seed, 32, out2, 64);
    
    bool deterministic = std::memcmp(out1, out2, 64) == 0;
    std::cout << "Same seed gives same output: " << (deterministic ? "✓" : "✗") << "\n";
    
    // Different seed should give different output
    seed[0] ^= 1;
    expand_seed(seed, 32, out2, 64);
    bool different = std::memcmp(out1, out2, 64) != 0;
    std::cout << "Different seed gives different output: " << (different ? "✓" : "✗") << "\n";
}

void test_derive_seed() {
    std::cout << "\n=== Test: derive_seed ===\n";
    
    uint8_t base[32] = {0};
    uint8_t derived1[32];
    uint8_t derived2[32];
    
    derive_seed(base, 0, derived1);
    derive_seed(base, 1, derived2);
    
    bool different = std::memcmp(derived1, derived2, 32) != 0;
    std::cout << "Different counters give different seeds: " << (different ? "✓" : "✗") << "\n";
    
    derive_seed(base, 0, derived2);
    bool same = std::memcmp(derived1, derived2, 32) == 0;
    std::cout << "Same counter gives same seed: " << (same ? "✓" : "✗") << "\n";
}

void test_hwt_sampling() {
    std::cout << "\n=== Test: HWT sampling ===\n";
    
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = 42 + i;
    
    // Test with TiGER128 parameters
    const auto &params = TIGER128_PARAMS;
    auto sparse = sample_hwt_sparse<512>(params.hs, seed);
    
    std::cout << "Requested hamming weight: " << params.hs << "\n";
    std::cout << "Actual non-zero count: " << sparse.size() << "\n";
    std::cout << (sparse.size() == params.hs ? "✓ Correct count\n" : "✗ Wrong count\n");
    
    print_sparse(sparse, "Sparse representation");
    
    // Verify uniqueness
    std::map<std::size_t, int> position_map;
    for (const auto &t : sparse) {
        position_map[t.index]++;
    }
    
    bool all_unique = true;
    for (const auto &[pos, count] : position_map) {
        if (count != 1) {
            all_unique = false;
            std::cout << "✗ Position " << pos << " appears " << count << " times!\n";
        }
    }
    if (all_unique) {
        std::cout << "✓ All positions unique\n";
    }
    
    // Test determinism
    auto sparse2 = sample_hwt_sparse<512>(params.hs, seed);
    bool deterministic = (sparse.size() == sparse2.size());
    if (deterministic) {
        for (std::size_t i = 0; i < sparse.size(); ++i) {
            if (sparse[i].index != sparse2[i].index || 
                sparse[i].sign != sparse2[i].sign) {
                deterministic = false;
                break;
            }
        }
    }
    std::cout << (deterministic ? "✓" : "✗") << " Deterministic sampling\n";
}

void test_hwt_polynomial() {
    std::cout << "\n=== Test: HWT polynomial form ===\n";
    
    uint8_t seed[32] = {1, 2, 3};
    auto poly = sample_hwt<512>(64, seed);
    
    std::size_t count_nonzero = 0;
    std::size_t count_plus_one = 0;
    std::size_t count_minus_one = 0;
    
    for (std::size_t i = 0; i < 512; ++i) {
        if (poly[i] != 0) {
            count_nonzero++;
            if (poly[i] == 1) count_plus_one++;
            else if (poly[i] == 255) count_minus_one++;  // -1 mod 256
        }
    }
    
    std::cout << "Non-zero coefficients: " << count_nonzero << " (expected 64)\n";
    std::cout << "  +1 count: " << count_plus_one << "\n";
    std::cout << "  -1 count: " << count_minus_one << "\n";
    std::cout << (count_nonzero == 64 ? "✓" : "✗") << " Correct hamming weight\n";
    
    // Test sparse conversion round-trip
    auto sparse = poly.to_sparse();
    Poly512 poly2;
    poly2.from_sparse(sparse);
    
    std::cout << (poly == poly2 ? "✓" : "✗") << " Sparse round-trip\n";
}

void test_uniform_sampling() {
    std::cout << "\n=== Test: Uniform sampling ===\n";
    
    uint8_t seed[32] = {0xFF};
    auto poly = sample_uniform<512>(seed);
    
    // Check all 256 values appear with roughly equal frequency
    std::map<uint8_t, int> histogram;
    for (std::size_t i = 0; i < 512; ++i) {
        histogram[poly[i]]++;
    }
    
    std::cout << "Unique values: " << histogram.size() << " / 256\n";
    std::cout << (histogram.size() > 200 ? "✓" : "✗") 
              << " Good distribution (>200 unique values)\n";
    
    // Determinism check
    auto poly2 = sample_uniform<512>(seed);
    std::cout << (poly == poly2 ? "✓" : "✗") << " Deterministic\n";
}

void test_all_security_levels() {
    std::cout << "\n=== Test: All security levels ===\n";
    
    SecurityLevel levels[] = {
        SecurityLevel::TIGER128,
        SecurityLevel::TIGER192,
        SecurityLevel::TIGER256
    };
    
    for (auto level : levels) {
        const auto &params = get_params(level);
        std::cout << "\n" << get_level_name(level) << ":\n";
        
        uint8_t seed[32] = {0};
        seed[0] = static_cast<uint8_t>(level);
        
        if (params.n == 512) {
            auto s = sample_hwt_sparse<512>(params.hs, seed);
            std::cout << "  hs=" << params.hs << ", sampled=" << s.size() 
                      << (s.size() == params.hs ? " ✓\n" : " ✗\n");
        } else {
            auto s = sample_hwt_sparse<1024>(params.hs, seed);
            std::cout << "  hs=" << params.hs << ", sampled=" << s.size() 
                      << (s.size() == params.hs ? " ✓\n" : " ✗\n");
        }
    }
}

int main() {
    std::cout << "=== TiGER Sampling Tests ===\n";
    
    try {
        test_random_bytes();
        test_expand_seed();
        test_derive_seed();
        test_hwt_sampling();
        test_hwt_polynomial();
        test_uniform_sampling();
        test_all_security_levels();
        
        std::cout << "\n=== All tests complete ===\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}

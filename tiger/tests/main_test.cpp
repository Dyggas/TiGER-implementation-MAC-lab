#include "../crypto/kem.cpp"
#include "../crypto/pke.cpp"
#include "../core/params.cpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <vector>

using namespace tiger;
using namespace std::chrono;

// ============================================================================
// Utilities
// ============================================================================

void print_hex(const uint8_t* data, size_t len, const char* label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(len, size_t(32)); ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) 
                  << int(data[i]);
    }
    if (len > 32) std::cout << "...";
    std::cout << std::dec << "\n";
}

void print_separator() {
    std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
}

bool arrays_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    return std::memcmp(a, b, len) == 0;
}

// ============================================================================
// PKE Tests
// ============================================================================

bool test_pke_basic(const TiGERParams& params) {
    std::cout << "\n[PKE] Testing " << get_level_name(params.level) << "\n";
    
    // Generate keypair
    auto start = high_resolution_clock::now();
    
    if (params.n == 512) {
        PKEPublicKey<512> pk;
        PKESecretKey<512> sk;
        pke_keygen(params, pk, sk);
        
        auto keygen_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
        std::cout << "  KeyGen: " << keygen_time.count() << " μs\n";
        
        // Prepare message
        std::vector<uint8_t> msg(params.d / 8);
        random_bytes(msg.data(), msg.size());
        

        
        // Encrypt
        uint8_t coin[32];
        random_bytes(coin, 32);
        std::vector<uint8_t> ct;
        
        start = high_resolution_clock::now();
        pke_encrypt(params, pk, msg.data(), coin, ct);
        auto encrypt_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
        std::cout << "  Encrypt: " << encrypt_time.count() << " μs\n";
        std::cout << "  Ciphertext size: " << ct.size() << " bytes (spec: " 
                  << params.ct_bytes << ")\n";
        print_hex(ct.data(), ct.size(), "  Ciphertext");
        
        // Decrypt
        std::vector<uint8_t> recovered(params.d / 8);
        start = high_resolution_clock::now();
        pke_decrypt(params, sk, ct.data(), recovered.data());
        auto decrypt_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
        std::cout << "  Decrypt: " << decrypt_time.count() << " μs\n";
    
        
        bool match = arrays_equal(msg.data(), recovered.data(), msg.size());
        std::cout << "  Message recovery: " << (match ? "✓ PASS" : "✗ FAIL") << "\n";
        
        if (!match) {
            print_hex(msg.data(), params.d / 8, "  Original ");
            print_hex(recovered.data(), params.d / 8, "  Recovered");
        }
        
        return match;
        
    } else {  // n == 1024
        PKEPublicKey<1024> pk;
        PKESecretKey<1024> sk;
        pke_keygen(params, pk, sk);
        
        auto keygen_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
        std::cout << "  KeyGen: " << keygen_time.count() << " μs\n";
        
        std::vector<uint8_t> msg(params.d / 8);
        for (size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
        }
        
        uint8_t coin[32];
        random_bytes(coin, 32);
        std::vector<uint8_t> ct;
        
        start = high_resolution_clock::now();
        pke_encrypt(params, pk, msg.data(), coin, ct);
        auto encrypt_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
        std::cout << "  Encrypt: " << encrypt_time.count() << " μs\n";
        std::cout << "  Ciphertext size: " << ct.size() << " bytes (spec: " 
                  << params.ct_bytes << ")\n";
        
        std::vector<uint8_t> recovered(params.d / 8);
        start = high_resolution_clock::now();
        pke_decrypt(params, sk, ct.data(), recovered.data());
        auto decrypt_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
        std::cout << "  Decrypt: " << decrypt_time.count() << " μs\n";
        
        bool match = arrays_equal(msg.data(), recovered.data(), msg.size());
        std::cout << "  Message recovery: " << (match ? "✓ PASS" : "✗ FAIL") << "\n";
        
        return match;
    }
}

bool test_pke_corrupted_ciphertext(const TiGERParams& params) {
    std::cout << "\n[PKE Error Test] Corrupted ciphertext - " 
              << get_level_name(params.level) << "\n";
    
    if (params.n == 512) {
        PKEPublicKey<512> pk;
        PKESecretKey<512> sk;
        pke_keygen(params, pk, sk);
        
        std::vector<uint8_t> msg(params.d / 8, 0xAA);
        uint8_t coin[32];
        random_bytes(coin, 32);
        std::vector<uint8_t> ct;
        pke_encrypt(params, pk, msg.data(), coin, ct);
        
        // Corrupt some bytes in ciphertext
        ct[0] ^= 0xFF;
        ct[ct.size() / 2] ^= 0xFF;
        ct[ct.size() - 1] ^= 0xFF;
        
        std::vector<uint8_t> recovered(params.d / 8);
        pke_decrypt(params, sk, ct.data(), recovered.data());
        
        bool match = arrays_equal(msg.data(), recovered.data(), msg.size());
        
        std::cout << "  Decryption with corrupted CT: " 
                  << (match ? "✗ INCORRECTLY succeeded" : "✓ Correctly failed/differed") << "\n";
        
        return !match;  // We EXPECT failure
    } else {
        PKEPublicKey<1024> pk;
        PKESecretKey<1024> sk;
        pke_keygen(params, pk, sk);
        
        std::vector<uint8_t> msg(params.d / 8, 0xAA);
        uint8_t coin[32];
        random_bytes(coin, 32);
        std::vector<uint8_t> ct;
        pke_encrypt(params, pk, msg.data(), coin, ct);
        
        ct[0] ^= 0xFF;
        ct[ct.size() / 2] ^= 0xFF;
        
        std::vector<uint8_t> recovered(params.d / 8);
        pke_decrypt(params, sk, ct.data(), recovered.data());
        
        bool match = arrays_equal(msg.data(), recovered.data(), msg.size());
        std::cout << "  Decryption with corrupted CT: " 
                  << (match ? "✗ INCORRECTLY succeeded" : "✓ Correctly failed/differed") << "\n";
        
        return !match;
    }
}

// ============================================================================
// KEM Tests
// ============================================================================

bool test_kem_basic(const TiGERParams& params) {
    std::cout << "\n[KEM] Testing " << get_level_name(params.level) << "\n";
    
    // KeyGen
    std::vector<uint8_t> pk, sk;
    auto start = high_resolution_clock::now();
    kem_keygen(params, pk, sk);
    auto keygen_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
    
    std::cout << "  KeyGen: " << keygen_time.count() << " μs\n";
    std::cout << "  PK size: " << pk.size() << " bytes (spec: " << params.pk_bytes << ")\n";
    std::cout << "  SK size: " << sk.size() << " bytes (spec: " << params.sk_bytes << ")\n";
    
    // Encaps
    std::vector<uint8_t> ct;
    std::array<uint8_t, 32> ss_enc;
    start = high_resolution_clock::now();
    kem_encaps(params, pk, ct, ss_enc);
    auto encaps_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
    
    std::cout << "  Encaps: " << encaps_time.count() << " μs\n";
    std::cout << "  CT size: " << ct.size() << " bytes (spec: " << params.ct_bytes << ")\n";
    
    // Decaps
    std::array<uint8_t, 32> ss_dec;
    start = high_resolution_clock::now();
    kem_decaps(params, pk, sk, ct, ss_dec);
    auto decaps_time = duration_cast<microseconds>(high_resolution_clock::now() - start);
    
    std::cout << "  Decaps: " << decaps_time.count() << " μs\n";
    
    // Verify
    bool match = arrays_equal(ss_enc.data(), ss_dec.data(), 32);
    std::cout << "  Shared secret match: " << (match ? "✓ PASS" : "✗ FAIL") << "\n";
    
    if (!match) {
        print_hex(ss_enc.data(), 32, "  SS (encaps)");
        print_hex(ss_dec.data(), 32, "  SS (decaps)");
    }
    
    return match;
}

bool test_kem_corrupted_ciphertext(const TiGERParams& params) {
    std::cout << "\n[KEM Error Test] Corrupted ciphertext - " 
              << get_level_name(params.level) << "\n";
    
    std::vector<uint8_t> pk, sk;
    kem_keygen(params, pk, sk);
    
    std::vector<uint8_t> ct;
    std::array<uint8_t, 32> ss_enc;
    kem_encaps(params, pk, ct, ss_enc);
    
    // Corrupt ciphertext
    ct[0] ^= 0xFF;
    ct[ct.size() / 2] ^= 0x01;
    
    std::array<uint8_t, 32> ss_dec;
    kem_decaps(params, pk, sk, ct, ss_dec);
    
    // With FO transform, decaps should succeed but return different SS
    bool match = arrays_equal(ss_enc.data(), ss_dec.data(), 32);
    std::cout << "  Shared secret match after corruption: " 
              << (match ? "✗ FAIL (should differ!)" : "✓ PASS (implicit reject)") << "\n";
    
    return !match;  // We EXPECT different SS
}

bool test_kem_wrong_secret_key(const TiGERParams& params) {
    std::cout << "\n[KEM Error Test] Wrong secret key - " 
              << get_level_name(params.level) << "\n";
    
    // Generate two independent keypairs
    std::vector<uint8_t> pk1, sk1, pk2, sk2;
    kem_keygen(params, pk1, sk1);
    kem_keygen(params, pk2, sk2);
    
    // Encaps with pk1
    std::vector<uint8_t> ct;
    std::array<uint8_t, 32> ss_enc;
    kem_encaps(params, pk1, ct, ss_enc);
    
    // Try to decaps with WRONG secret key (sk2)
    std::array<uint8_t, 32> ss_dec;
    kem_decaps(params, pk1, sk2, ct, ss_dec);  // Wrong SK!
    
    bool match = arrays_equal(ss_enc.data(), ss_dec.data(), 32);
    std::cout << "  Shared secret match with wrong key: " 
              << (match ? "✗ FAIL (should differ!)" : "✓ PASS (rejected)") << "\n";
    
    return !match;
}

// ============================================================================
// Performance Benchmark
// ============================================================================

void benchmark_kem(const TiGERParams& params, int iterations = 100) {
    std::cout << "\n[Benchmark] " << get_level_name(params.level) 
              << " (" << iterations << " iterations)\n";
    
    long long total_keygen = 0, total_encaps = 0, total_decaps = 0;
    
    for (int i = 0; i < iterations; ++i) {
        std::vector<uint8_t> pk, sk;
        auto start = high_resolution_clock::now();
        kem_keygen(params, pk, sk);
        total_keygen += duration_cast<microseconds>(high_resolution_clock::now() - start).count();
        
        std::vector<uint8_t> ct;
        std::array<uint8_t, 32> ss_enc;
        start = high_resolution_clock::now();
        kem_encaps(params, pk, ct, ss_enc);
        total_encaps += duration_cast<microseconds>(high_resolution_clock::now() - start).count();
        
        std::array<uint8_t, 32> ss_dec;
        start = high_resolution_clock::now();
        kem_decaps(params, pk, sk, ct, ss_dec);
        total_decaps += duration_cast<microseconds>(high_resolution_clock::now() - start).count();
    }
    
    std::cout << "  Avg KeyGen:  " << (total_keygen / iterations) << " μs\n";
    std::cout << "  Avg Encaps:  " << (total_encaps / iterations) << " μs\n";
    std::cout << "  Avg Decaps:  " << (total_decaps / iterations) << " μs\n";
    std::cout << "  Total cycle: " << ((total_keygen + total_encaps + total_decaps) / iterations) << " μs\n";
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "╔══════════════════════════════════════════════════╗\n";
    std::cout << "║       TiGER Full Cryptographic Test Suite        ║\n";
    std::cout << "╚══════════════════════════════════════════════════╝\n";
    
    SecurityLevel levels[] = {
        SecurityLevel::TIGER128,
        SecurityLevel::TIGER192,
        SecurityLevel::TIGER256
    };
    
    int total_tests = 0;
    int passed_tests = 0;
    
    for (auto level : levels) {
        print_separator();
        const TiGERParams& params = get_params(level);
        
        // PKE tests
        total_tests++;
        if (test_pke_basic(params)) passed_tests++;
        
        total_tests++;
        if (test_pke_corrupted_ciphertext(params)) passed_tests++;
        
        // KEM tests
        total_tests++;
        if (test_kem_basic(params)) passed_tests++;
        
        total_tests++;
        if (test_kem_corrupted_ciphertext(params)) passed_tests++;
        
        total_tests++;
        if (test_kem_wrong_secret_key(params)) passed_tests++;
        
        // Benchmark
        benchmark_kem(params, 100);
    }
    
    print_separator();
    std::cout << "\n╔══════════════════════════════════════════════════╗\n";
    std::cout << "║                 Test Summary                     ║\n";
    std::cout << "╠══════════════════════════════════════════════════╣\n";
    std::cout << "║  Total tests:  " << std::setw(2) << total_tests << "                                ║\n";
    std::cout << "║  Passed:       " << std::setw(2) << passed_tests << "                                ║\n";
    std::cout << "║  Failed:       " << std::setw(2) << (total_tests - passed_tests) << "                                ║\n";
    std::cout << "╚══════════════════════════════════════════════════╝\n";
    
    if (passed_tests == total_tests) {
        std::cout << "\n✓✓✓ ALL TESTS PASSED ✓✓✓\n";
        return 0;
    } else {
        std::cout << "\n✗✗✗ SOME TESTS FAILED ✗✗✗\n";
        return 1;
    }
}

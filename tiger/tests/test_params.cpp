#include <iostream>
#include "../core/params.cpp"

using namespace tiger;

int main() {
    std::cout << "=== TiGER Parameter Validation ===\n\n";
    
    // Test all three parameter sets
    SecurityLevel levels[] = {
        SecurityLevel::TIGER128,
        SecurityLevel::TIGER192,
        SecurityLevel::TIGER256
    };
    
    bool all_valid = true;
    
    for (auto level : levels) {
        const TiGERParams &params = get_params(level);
        
        std::cout << "Testing " << get_level_name(level) << "...\n";
        
        bool valid = validate_params(params);
        if (valid) {
            std::cout << "✓ Validation passed\n\n";
            print_params(params);
            std::cout << "\n";
        } else {
            std::cout << "✗ Validation FAILED\n\n";
            all_valid = false;
        }
    }
    
    // Test helper functions
    std::cout << "=== Helper Function Tests ===\n";
    std::cout << "log2_pow2(64) = " << log2_pow2(64) << " (expect 6)\n";
    std::cout << "log2_pow2(128) = " << log2_pow2(128) << " (expect 7)\n";
    std::cout << "is_power_of_2(64) = " << is_power_of_2(64) << " (expect 1)\n";
    std::cout << "is_power_of_2(65) = " << is_power_of_2(65) << " (expect 0)\n";
    
    std::cout << "\n=== Size Computation Verification ===\n";
    for (auto level : levels) {
        const TiGERParams &params = get_params(level);
        std::cout << get_level_name(level) << ":\n";
        std::cout << "  pk: " << compute_pk_bytes(params) << " bytes\n";
        std::cout << "  sk: " << compute_sk_bytes(params) << " bytes\n";
        std::cout << "  ct: " << compute_ct_bytes(params) << " bytes\n";
    }
    
    return all_valid ? 0 : 1;
}

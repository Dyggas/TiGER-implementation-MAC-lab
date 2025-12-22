#include "sampling.hpp"
#include <cstring>
#include <stdexcept>

// Platform-specific includes for random bytes (voodoo magic)
#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <fcntl.h>
    #include <unistd.h>
#endif

namespace tiger {

void random_bytes(uint8_t *out, std::size_t len) {
#ifdef _WIN32
    // Windows: use BCryptGenRandom
    if (BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), 
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    // Unix/Linux: read from /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("Failed to open /dev/urandom");
    }
    
    std::size_t total_read = 0;
    while (total_read < len) {
        ssize_t n = read(fd, out + total_read, len - total_read);
        if (n <= 0) {
            close(fd);
            throw std::runtime_error("Failed to read from /dev/urandom");
        }
        total_read += n;
    }
    
    close(fd);
#endif
}


void expand_seed(const uint8_t *seed, std::size_t seed_len,
                 uint8_t *out, std::size_t out_len) {
    shake256_hash(seed, seed_len, out, out_len);
}

void derive_seed(const uint8_t base_seed[32], uint32_t counter,
                 uint8_t derived_seed[32]) {
    // Simple domain separation: hash (base_seed || counter)
    uint8_t input[36];
    std::memcpy(input, base_seed, 32);
    input[32] = static_cast<uint8_t>(counter & 0xFF);
    input[33] = static_cast<uint8_t>((counter >> 8) & 0xFF);
    input[34] = static_cast<uint8_t>((counter >> 16) & 0xFF);
    input[35] = static_cast<uint8_t>((counter >> 24) & 0xFF);
    
    shake256_hash(input, 36, derived_seed, 32);
}

// Explicit template instantiations
template Polynomial<512> sample_hwt<512>(std::size_t, const uint8_t[32]);
template Polynomial<1024> sample_hwt<1024>(std::size_t, const uint8_t[32]);

template std::vector<SparseTernary> sample_hwt_sparse<512>(std::size_t, const uint8_t[32]);
template std::vector<SparseTernary> sample_hwt_sparse<1024>(std::size_t, const uint8_t[32]);

template Polynomial<512> sample_uniform<512>(const uint8_t[32]);
template Polynomial<1024> sample_uniform<1024>(const uint8_t[32]);

} // namespace tiger

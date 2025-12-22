#pragma once

#include "params.hpp"

#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace tiger {

// SparseTernary
struct SparseTernary {
    std::size_t index;
    int8_t      sign;   // +1 or -1
};

// Polynomial template

template<std::size_t N>
class Polynomial {
public:
    static_assert(N == 512 || N == 1024, "N must be 512 or 1024");

    // Constructors
    Polynomial() = default;
    explicit Polynomial(uint8_t constant) : coeffs_{} { coeffs_[0] = constant; }
    explicit Polynomial(const std::array<uint8_t, N> &c) : coeffs_(c) {}

    static Polynomial zero() { return Polynomial(); }
    static Polynomial constant(uint8_t v) { return Polynomial(v); }

    std::size_t size() const { return N; }
    uint8_t *data() { return coeffs_.data(); }
    const uint8_t *data() const { return coeffs_.data(); }
    uint8_t &operator[](std::size_t i) { return coeffs_[i]; }
    const uint8_t &operator[](std::size_t i) const { return coeffs_[i]; }

    // Arithmetic
    Polynomial operator+(const Polynomial &o) const {
        Polynomial r;
        for (std::size_t i = 0; i < N; ++i) r[i] = coeffs_[i] + o[i];
        return r;
    }

    Polynomial operator-(const Polynomial &o) const {
        Polynomial r;
        for (std::size_t i = 0; i < N; ++i) r[i] = coeffs_[i] - o[i];
        return r;
    }

    Polynomial &operator+=(const Polynomial &o) {
        for (std::size_t i = 0; i < N; ++i) coeffs_[i] += o[i];
        return *this;
    }

    Polynomial &operator-=(const Polynomial &o) {
        for (std::size_t i = 0; i < N; ++i) coeffs_[i] -= o[i];
        return *this;
    }

    Polynomial operator-() const {
        Polynomial r;
        for (std::size_t i = 0; i < N; ++i) r[i] = -coeffs_[i];
        return r;
    }

    Polynomial operator*(uint8_t s) const {
        Polynomial r;
        for (std::size_t i = 0; i < N; ++i) r[i] = coeffs_[i] * s;
        return r;
    }

    Polynomial &operator*=(uint8_t s) {
        for (std::size_t i = 0; i < N; ++i) coeffs_[i] *= s;
        return *this;
    }

    // Multiplication
    Polynomial operator*(const Polynomial &o) const {
        return multiply_schoolbook(*this, o);
    }

    Polynomial multiply_sparse(const std::vector<SparseTernary> &s) const {
        return multiply_sparse_ternary(*this, s);
    }

    // Scale and round
    Polynomial scale_round(uint32_t num, uint32_t den) const {
        Polynomial r;
        for (std::size_t i = 0; i < N; ++i) {
            uint32_t x = static_cast<uint32_t>(coeffs_[i]) * num;
            r[i] = static_cast<uint8_t>((x + den / 2u) / den); // Round to nearest trick + hack 
        }
        return r;
    }

    Polynomial scale(uint32_t f) const {
        Polynomial r;
        for (std::size_t i = 0; i < N; ++i) {
            r[i] = static_cast<uint8_t>((coeffs_[i] * f) & 0xFFu);
        }
        return r;
    }

    // Serialization
    void serialize(uint8_t *out) const { std::memcpy(out, coeffs_.data(), N); }
    void deserialize(const uint8_t *in) { std::memcpy(coeffs_.data(), in, N); }

    // Compression (bit packing)
    void compress(uint8_t *out, uint8_t log_mod) const {
        if (log_mod == 8) {
            std::memcpy(out, coeffs_.data(), N);
            return;
        }
        const uint8_t shift = 8u - log_mod;
        uint32_t buf = 0, bits = 0;
        std::size_t oidx = 0;

        // Sliding byte-sized window + packing log_mod bits at a time
        for (std::size_t i = 0; i < N; ++i) {
            uint8_t c = (coeffs_[i] >> shift); // Keep the top log_mod bits
            buf |= (static_cast<uint32_t>(c) << bits);
            bits += log_mod;
            // Flush bytes when we have enough
            while (bits >= 8) {
                out[oidx++] = static_cast<uint8_t>(buf & 0xFFu);
                buf >>= 8; // Remove flushed byte
                bits -= 8;
            }
        }
        if (bits) out[oidx] = static_cast<uint8_t>(buf & 0xFFu); 
    }

    // Decompression (bit unpacking) :)
    void decompress(const uint8_t *in, uint8_t log_mod) {
        if (log_mod == 8) {
            std::memcpy(coeffs_.data(), in, N);
            return;
        }
        const uint8_t shift = 8u - log_mod;
        uint32_t buf = 0, bits = 0;
        std::size_t iidx = 0;
        // Sliding byte-sized window + unpacking log_mod bits at a time
        for (std::size_t i = 0; i < N; ++i) {
            while (bits < log_mod) {
                buf |= (static_cast<uint32_t>(in[iidx++]) << bits);
                bits += 8;
            }
            uint32_t c = buf & ((1u << log_mod) - 1u);
            coeffs_[i] = static_cast<uint8_t>(c << shift);
            buf >>= log_mod;
            bits -= log_mod;
        }
    }

    // Sparse
    std::vector<SparseTernary> to_sparse() const {
        std::vector<SparseTernary> r;
        r.reserve(N / 4);
        for (std::size_t i = 0; i < N; ++i) {
            if (coeffs_[i] == 1) r.push_back({i, 1});
            else if (coeffs_[i] == 255) r.push_back({i, -1});
        }
        return r;
    }

    void from_sparse(const std::vector<SparseTernary> &s) {
        std::memset(coeffs_.data(), 0, N);
        for (const auto &t : s) {
            coeffs_[t.index] = (t.sign > 0) ? 1u : 255u;
        }
    }

    bool operator==(const Polynomial &o) const {
        return std::memcmp(coeffs_.data(), o.coeffs_.data(), N) == 0;
    }

    bool operator!=(const Polynomial &o) const { return !(*this == o); }

    // Constant-time equality (to avoid timing attacks); just xor and or all differences
    bool ct_equal(const Polynomial &o) const {
        uint8_t d = 0;
        for (std::size_t i = 0; i < N; ++i) d |= (coeffs_[i] ^ o[i]);
        return d == 0;
    }

private:
    std::array<uint8_t, N> coeffs_{};
};

// Non-member functions
template<std::size_t N>
Polynomial<N> multiply_schoolbook(const Polynomial<N> &a, const Polynomial<N> &b) {
    std::array<int16_t, 2 * N> t{};
    for (std::size_t i = 0; i < N; ++i) {
        int16_t ai = static_cast<int16_t>(a[i]);
        for (std::size_t j = 0; j < N; ++j) {
            t[i + j] += static_cast<int16_t>(b[j]) * ai;
        }
    }
    Polynomial<N> r;
    for (std::size_t i = 0; i < N; ++i) {
        int16_t v = t[i] - t[i + N];
        r[i] = static_cast<uint8_t>(v & 0xFF);
    }
    return r;
}

template<std::size_t N>
Polynomial<N> multiply_sparse_ternary(const Polynomial<N> &d,
                                      const std::vector<SparseTernary> &s) {
    std::array<int16_t, N> acc{};
    for (const auto &t : s) {
        int16_t sign = static_cast<int16_t>(t.sign);
        for (std::size_t i = 0; i < N; ++i) {
            std::size_t pos = i + t.index;
            int16_t val = static_cast<int16_t>(d[i]) * sign;
            if (pos >= N) {
                pos -= N;
                val = -val;
            }
            acc[pos] += val;
        }
    }
    Polynomial<N> r;
    for (std::size_t i = 0; i < N; ++i) r[i] = static_cast<uint8_t>(acc[i] & 0xFF);
    return r;
}

template<std::size_t N>
bool constant_time_equal(const Polynomial<N> &a, const Polynomial<N> &b) {
    uint8_t d = 0;
    for (std::size_t i = 0; i < N; ++i) d |= (a[i] ^ b[i]);
    return d == 0;
}

template<std::size_t N>
void constant_time_select(Polynomial<N> &r, const Polynomial<N> &t,
                          const Polynomial<N> &f, uint8_t cond) {
    uint8_t m = static_cast<uint8_t>(-(cond & 1u));
    for (std::size_t i = 0; i < N; ++i) {
        r[i] = static_cast<uint8_t>((m & t[i]) | (~m & f[i]));
    }
}

// Aliases
using Poly512  = Polynomial<512>;
using Poly1024 = Polynomial<1024>;

} // namespace tiger

#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <cstring>

#include "../core/params.hpp"
#include "../core/polynomial.hpp"

using namespace tiger;

template<std::size_t N>
void print_poly(const Polynomial<N> &p, const char *label, std::size_t max_terms = 8) {
    std::cout << label << " (first " << max_terms << " coeffs): ";
    for (std::size_t i = 0; i < max_terms && i < N; ++i) {
        std::cout << int(p[i]) << (i + 1 < max_terms ? ' ' : '\n');
    }
}

int main() {
    std::cout << "=== TiGER core tests ===\n";

    // 1. Basic construction and addition/subtraction
    Poly512 a, b;
    a[0] = 100;
    a[1] = 250;
    b[0] = 200;
    b[1] = 10;

    std::cout << "\n[1] Basic arithmetic\n";
    print_poly(a, "a");
    print_poly(b, "b");

    auto sum = a + b;      // 100+200=44 mod256, 250+10=4 mod256
    auto diff = a - b;     // 100-200=156 mod256, 250-10=240
    auto neg = -a;         // -100 mod256=156, -250=6

    print_poly(sum,  "a + b");
    print_poly(diff, "a - b");
    print_poly(neg,  "-a");

    // 2. Scalar multiplication
    std::cout << "\n[2] Scalar multiplication\n";
    auto scaled = a * uint8_t(3);
    print_poly(scaled, "a * 3"); // 100*3=44, 250*3=238 mod256

    // 3. Schoolbook multiplication with negacyclic reduction
    std::cout << "\n[3] Polynomial multiplication (schoolbook, negacyclic)\n";

    Poly512 x, y;
    x[0] = 1;   // 1
    x[1] = 1;   // X
    y[0] = 1;   // 1
    y[1] = 1;   // X

    // (1 + X) * (1 + X) = 1 + 2X + X^2  (no wrap for small degrees)
    auto prod = x * y;
    print_poly(x,    "x");
    print_poly(y,    "y");
    print_poly(prod, "x * y", 4);

    // Negacyclic check: (X^{N-1} + 1) * X = X^N + X = -1 + X = 255 + X
    Poly512 u, v;
    u[0]           = 1;  // 1
    u[TIGER_N_128 - 1] = 1;  // X^{N-1}
    v[1]           = 1;  // X

    auto negacyclic_test = u * v;
    print_poly(u, "u = 1 + X^{N-1}", 4);
    print_poly(v, "v = X", 4);
    print_poly(negacyclic_test, "u * v (expecting - 1 + X at positions 1 and 0)", 4);

    // 4. Sparse ternary multiplication
    std::cout << "\n[4] Sparse ternary multiplication\n";

    Poly512 dense;
    dense[0] = 5;   // 5
    dense[1] = 10;  // 10X

    // s(X) = 1 - X^2  (positions 0 and 2)
    std::vector<SparseTernary> sparse = {
        {0,  1},
        {2, -1}
    };

    auto sparse_prod = dense.multiply_sparse(sparse);
    print_poly(dense,      "dense", 6);
    std::cout << "sparse terms: ";
    for (auto &t : sparse) {
        std::cout << "(" << t.index << "," << int(t.sign) << ") ";
    }
    std::cout << "\n";
    print_poly(sparse_prod, "dense * sparse", 6);

    // 5. Scale and round (RLWR)
    std::cout << "\n[5] Scale and round\n";

    Poly512 r;
    r[0] = 128; // q/2
    r[1] = 200;

    // Example: ⌊(p/q)*r⌉ with p=128, q=256 => multiply by 1/2
    auto scaled_round = r.scale_round(128, 256);
    print_poly(r,           "r");
    print_poly(scaled_round,"scale_round(r, 128/256)");

    // Plain scale
    auto scaled_plain = r.scale(2); // multiply by 2 mod 256
    print_poly(scaled_plain, "scale(r, 2)");

    // 6. Serialization, compression, decompression
    std::cout << "\n[6] Serialization + compression\n";

    // Serialize a polynomial
    uint8_t buffer_raw[512]{};
    a.serialize(buffer_raw);

    Poly512 a_deser;
    a_deser.deserialize(buffer_raw);
    std::cout << "a == a_deser? " << (a == a_deser ? "yes" : "no") << "\n";

    // Compress with log_modulus = 6 bits (p=64 or k1=64 in TiGER128)
    constexpr uint8_t LOG_MOD = 6;
    // Each coeff -> 6 bits, 512*6 = 3072 bits = 384 bytes
    uint8_t buffer_comp[384]{};
    uint8_t buffer_decomp_raw[512]{};

    // a is still 100 + 250X + ...
    a.compress(buffer_comp, LOG_MOD);

    Poly512 a_decomp;
    a_decomp.decompress(buffer_comp, LOG_MOD);
    a_decomp.serialize(buffer_decomp_raw);

    std::cout << "Compression/decompression done (6 bits per coeff) -> bottom two bits will be lost.\n";
    std::cout << "First few coeffs pre/post:\n";
    for (std::size_t i = 0; i < 8; ++i) {
        std::cout << "  i=" << i
                  << " orig=" << int(a[i])
                  << " decomp=" << int(a_decomp[i])
                  << "\n";
    }

    // 7. Sparse conversion + constant-time equality
    std::cout << "\n[7] Sparse convert + constant-time equality\n";

    // Make a sparse polynomial p with some ±1 entries
    Poly512 p;
    p[0] = 1;
    p[5] = 255;  // -1 mod 256
    p[10] = 1;

    auto sparse_repr = p.to_sparse();
    std::cout << "p sparse representation:\n";
    for (auto &t : sparse_repr) {
        std::cout << "  index=" << t.index << ", sign=" << int(t.sign) << "\n";
    }

    Poly512 p_recovered;
    p_recovered.from_sparse(sparse_repr);

    std::cout << "p == p_recovered? " << (p == p_recovered ? "yes" : "no") << "\n";
    std::cout << "ct_equal(p, p_recovered)? "
              << (p.ct_equal(p_recovered) ? "yes" : "no") << "\n";

    // Check that ct_equal distinguishes differences
    Poly512 p_modified = p;
    p_modified[0] ^= 1; // flip a bit

    std::cout << "ct_equal(p, p_modified)? "
              << (p.ct_equal(p_modified) ? "yes" : "no") << "\n";

    std::cout << "\n=== Done 4 now B) ===\n";
    return 0;
}

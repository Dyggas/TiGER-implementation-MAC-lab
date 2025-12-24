# TiGER-implementation-MAC-lab

This project implements the TiGER public-key encryption (IND-CPA PKE) and the TiGER IND-CCA KEM on top of it.  
The implementation is written in C++ and includes polynomial arithmetic in $R_q = \mathbb{Z}_{256}[X]/(X^n+1)$, sparse ternary sampling, message ECC (XEf + D2), key/ciphertext serialization, and KEM encapsulation/decapsulation.

## Implemented features

### Parameter sets
Implements TiGER parameter structs and predefined parameter sets for TiGER128/TiGER192/TiGER256 (n, q, p, k1, k2, hs, hr, he, d, f, sizes) in `tiger/core/params.hpp`

### Polynomial ring arithmetic
Polynomial coefficients are stored as bytes `uint8_t` (implicit $mod\; 256$ arithmetic). 
Supports addition/subtraction, negation, scalar multiply, schoolbook multiply, and sparse ternary multiply optimized via sparse index/sign representation.

### Sampling
Implements:
- Uniform sampling of public polynomial `a` from `seed_a` (SHAKE-based expansion).
- Sparse ternary sampling `HWT_n(h, seed)` for secret `s`, ephemeral `r`, and errors `e1/e2`.

### ECC message processing
Implements the TiGER message redundancy pipeline:
- XEf encode/decode (XE1 .. XE5 depending on parameters) for error correction.
- D2 encoding (duplicate bits into two coefficients) and decoding (pairwise thresholding).

### IND-CPA PKE
Implements the three PKE algorithms:
- `pke_keygen`: generates `(seed_a, b)` and `s`.
- `pke_encrypt`: encrypts `msg` with randomness `coin`, producing `(c1||c2)`.
- `pke_decrypt`: decrypts `(c1||c2)` using `s`, performs the \(2/q\) rounding step, then ECC decoding.

### IND-CCA KEM (FO transform)
Implements:
- `kem_keygen`: outputs `(pk, sk=(s||u))` (with random fallback string `u`).
- `kem_encaps`: samples `delta`, encrypts `delta` under `H(delta)`, derives shared secret as `G(c || delta)`.
- `kem_decaps`: decrypts to `delta_hat`, recomputes ciphertext, constant-time compares ciphertexts, derives `G(c || delta_hat)` if match else `G(c || u)`.

### Serialization / packing
Implements packing and unpacking for:
- Public key `(seed_a || b)` 
- Secret key `(s || u)` 
- Ciphertext `(c1 || c2)` 

Compression uses bit-packing based on `log2(k)` bits per coefficient.

#### Note:
- XEf encoding, Shake256 and SHA3-256 were taken from open sources.

## Security / attack protections included

### Chosen-ciphertext (IND-CCA) protection
Decapsulation uses the FO transform: re-encrypt after decrypt, compare ciphertexts, and conditionally derive the shared secret from `delta_hat` or `u`.   
This prevents attackers from using decapsulation as a “decryption oracle” for arbitrary ciphertexts. 

### Constant-time ciphertext comparison
Ciphertext equality is checked using a constant-time byte comparison (`diff |= a[i] ^ b[i]`), preventing timing leakage on early mismatch. 

### ECC to reduce decryption failure
TiGER uses D2 + XEf to tolerate noise and compression error while maintaining a negligible decryption failure rate (per spec :))).

### Deterministic key material reconstruction
Public polynomial `a` is deterministically reconstructed from `seed_a` rather than transmitted in full, reducing bandwidth and ensuring consistent reconstruction. 

## How to run

### Execute tests

- Run `main_test.cpp`.   

Program was tested with MinGW compiler on Windows platform.

#### Note:

- Usual architecture conventions like `only include header files, just add cpp files to compilation command!` have been neglected for the sake of convenience and lack of time to set up IDE.

## Struggles (many)

- While the initial project structure worked pretty well, failing to comply to it and compartmentalize algorithm steps led to a wide array of obscure and hard-to-point-out bugs. While effectively doubling `scale_round` (dividing polynomial coefficients to "normalize" them) in `pke.cpp` and then in `d2.cpp` should have been easy to spot (output being zeros), it wasn't. And then, forgetting to clean up and normalize `diff` - differenc of $c_1$ and $c_2$ was soul-crushing.

- Confusion in using the *borrowed* XEf encoding implementation (lost me some time).

- Differences in implementation parameters:
    - I initially started implementing the algorithm in `TiGER.pdf`, the one submitted to KqpC competition and the that could be recovered using Web archive from their website. This lost me countless (not really) hours since the one actually working (in their implementation on GitHub) has different ones. Was it due to a theoretical mistake or a practical one, idk.
    - And then, when I checked my friend's theory, the parameters were so drastically different, I started doubting my sanity. Oh well. 
    - In the end, I hand picked the parameters that work. Spoiler alert: they are not optimal, that was not my goal.

- The choice to implement such a thing in C/C++ in a time crunch was definitely one of the choices of all time. Segmentation fault for the win! The performance looks good IMO though.

## Final output
A successful run prints `✓ PASS` for both PKE and KEM tests for each parameter set being tested.   
Example structure:
- `[PKE] Testing TiGER128 ... Message recovery: ✓ PASS`   
- `[KEM] Testing TiGER128 ... Shared secret match: ✓ PASS` 

```
╔══════════════════════════════════════════════════╗
║       TiGER Full Cryptographic Test Suite        ║
╚══════════════════════════════════════════════════╝
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[PKE] Testing TiGER128
  KeyGen: 29434 μs
  Encrypt: 4645 μs
  Ciphertext size: 1024 bytes (spec: 1024)
  Ciphertext: 24768c711420603d6e5124fb9db7974a64889ebcd1c9c5ed6213754835bca179...
  Decrypt: 1919 μs
  Message recovery: ✓ PASS
  Original : 8f7c8adbe4f2991ae3fbf75979f81864
  Recovered: 8f7c8adbe4f2991ae3fbf75979f81864

[KEM] Testing TiGER128
  KeyGen: 3063 μs
  PK size: 480 bytes (spec: 480)
  SK size: 528 bytes (spec: 528)
  Encaps: 7909 μs
  CT size: 1024 bytes (spec: 1024)
  Decaps: 5847 μs
  Shared secret match: ✓ PASS
  SS (encaps): 55fbbf24e8eac1ab0fc5757bd95d13940ea2d62c3f937ec58cc1309f006fb3a9
  SS (decaps): 55fbbf24e8eac1ab0fc5757bd95d13940ea2d62c3f937ec58cc1309f006fb3a9

[KEM Error Test] Wrong secret key - TiGER128
  Shared secret match with wrong key: ✓ PASS (rejected)

[Benchmark] TiGER128 (100 iterations)
  Avg KeyGen:  2176 μs
  Avg Encaps:  4241 μs
  Avg Decaps:  5610 μs
  Total cycle: 12029 μs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[PKE] Testing TiGER192
  KeyGen: 2043 μs
  Encrypt: 5127 μs
  Ciphertext size: 1792 bytes (spec: 1792)
  Decrypt: 2864 μs
  Message recovery: ✓ PASS
  Original : 0d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6
  Recovered: 0d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6

[KEM] Testing TiGER192
  KeyGen: 2767 μs
  PK size: 928 bytes (spec: 928)
  SK size: 1056 bytes (spec: 1056)
  Encaps: 4998 μs
  CT size: 1792 bytes (spec: 1792)
  Decaps: 8899 μs
  Shared secret match: ✓ PASS
  SS (encaps): e78dec90b342a090fa82a1831a6a7d77af948828fbb1b39e5b05ba86274424c3
  SS (decaps): e78dec90b342a090fa82a1831a6a7d77af948828fbb1b39e5b05ba86274424c3

[KEM Error Test] Wrong secret key - TiGER192
  Shared secret match with wrong key: ✓ PASS (rejected)

[Benchmark] TiGER192 (100 iterations)
  Avg KeyGen:  2335 μs
  Avg Encaps:  5771 μs
  Avg Decaps:  7037 μs
  Total cycle: 15144 μs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[PKE] Testing TiGER256
  KeyGen: 7761 μs
  Encrypt: 9296 μs
  Ciphertext size: 1792 bytes (spec: 1792)
  Decrypt: 2710 μs
  Message recovery: ✓ PASS
  Original : 0d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6
  Recovered: 0d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6

[KEM] Testing TiGER256
  KeyGen: 3783 μs
  PK size: 928 bytes (spec: 928)
  SK size: 1056 bytes (spec: 1056)
  Encaps: 10166 μs
  CT size: 1792 bytes (spec: 1792)
  Decaps: 16745 μs
  Shared secret match: ✓ PASS
  SS (encaps): 9d62e06c8d8ed4086e30a07fe06a047a77d46e9ddb047a0050497aa2abe77c82
  SS (decaps): 9d62e06c8d8ed4086e30a07fe06a047a77d46e9ddb047a0050497aa2abe77c82

[KEM Error Test] Wrong secret key - TiGER256
  Shared secret match with wrong key: ✓ PASS (rejected)

[Benchmark] TiGER256 (100 iterations)
  Avg KeyGen:  4662 μs
  Avg Encaps:  11139 μs
  Avg Decaps:  13440 μs
  Total cycle: 29242 μs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╔══════════════════════════════════════════════════╗
║                 Test Summary                     ║
╠══════════════════════════════════════════════════╣
║  Total tests:                                   9║
║  Passed:                                        9║
║  Failed:                                        0║
╚══════════════════════════════════════════════════╝

✓✓✓ ALL TESTS PASSED ✓✓✓
```
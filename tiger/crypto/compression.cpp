#pragma once
#include "compression.hpp"

namespace tiger {

// Explicit instantiations (BoIlErPlAtE)
template void pack_public_key<512>(const std::array<uint8_t, 32>&, 
    const Polynomial<512>&, const TiGERParams&, uint8_t*);
template void pack_public_key<1024>(const std::array<uint8_t, 32>&, 
    const Polynomial<1024>&, const TiGERParams&, uint8_t*);

template void unpack_public_key<512>(const uint8_t*, const TiGERParams&, 
    std::array<uint8_t, 32>&, Polynomial<512>&);
template void unpack_public_key<1024>(const uint8_t*, const TiGERParams&, 
    std::array<uint8_t, 32>&, Polynomial<1024>&);

template void pack_secret_key<512>(const Polynomial<512>&, 
    const uint8_t*, std::size_t, uint8_t*);
template void pack_secret_key<1024>(const Polynomial<1024>&, 
    const uint8_t*, std::size_t, uint8_t*);

template void unpack_secret_key<512>(const uint8_t*, std::size_t, 
    Polynomial<512>&, uint8_t*);
template void unpack_secret_key<1024>(const uint8_t*, std::size_t, 
    Polynomial<1024>&, uint8_t*);

template void pack_ciphertext<512>(const Polynomial<512>&, 
    const Polynomial<512>&, const TiGERParams&, uint8_t*);
template void pack_ciphertext<1024>(const Polynomial<1024>&, 
    const Polynomial<1024>&, const TiGERParams&, uint8_t*);

template void unpack_ciphertext<512>(const uint8_t*, const TiGERParams&, 
    Polynomial<512>&, Polynomial<512>&);
template void unpack_ciphertext<1024>(const uint8_t*, const TiGERParams&, 
    Polynomial<1024>&, Polynomial<1024>&);

} // namespace tiger

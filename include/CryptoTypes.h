// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, The Karbo developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <cstdint>
#include <crypto/crypto-util.h>

namespace Crypto {

#pragma pack(push, 1)
struct EllipticCurvePoint {
  uint8_t data[32];
};

struct EllipticCurveScalar {
  uint8_t data[32];
};

struct Hash {
  uint8_t data[32];
};

struct PublicKey {
  uint8_t data[32];
};

struct SecretKey {
  uint8_t data[32];
  ~SecretKey() { sodium_memzero(data, sizeof(data)); }
};

struct KeyDerivation {
  uint8_t data[32];
};

struct KeyImage {
  uint8_t data[32];
};

struct Signature {
  uint8_t data[64];
};
#pragma pack(pop)

static_assert(sizeof(EllipticCurvePoint) == 32 && sizeof(EllipticCurveScalar) == 32, "Invalid structure size");

static_assert(sizeof(Hash) == 32 && sizeof(PublicKey) == 32 && sizeof(SecretKey) == 32 && sizeof(KeyDerivation) == 32 &&
  sizeof(KeyImage) == 32 && sizeof(Signature) == 64, "Invalid structure size");

} // namespace Crypto

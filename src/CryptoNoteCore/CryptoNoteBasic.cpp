// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2019, The Karbowanec developers
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

#include "CryptoNoteBasic.h"
#include "crypto/crypto.h"

namespace CryptoNote {

KeyPair generateKeyPair() {
  KeyPair k;
  Crypto::generate_keys(k.publicKey, k.secretKey);
  return k;
}

int getAlgo(const Block& b) {
  switch (b.algorithm)
  {
  case CURRENCY_BLOCK_POW_TYPE_CN:
    return ALGO_CN;
  case CURRENCY_BLOCK_POW_TYPE_CN_GPU:
    return ALGO_CN_GPU;
  case CURRENCY_BLOCK_POW_TYPE_CN_HEAVY:
    return ALGO_CN_HEAVY;
  case CURRENCY_BLOCK_POW_TYPE_RANDOMX:
    return ALGO_RANDOMX;
  }
  //return ALGO_UNKNOWN;
  return ALGO_CN;
}

}

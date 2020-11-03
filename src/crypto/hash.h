// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2020, Karbo developers
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

#include <stddef.h>

#include <CryptoTypes.h>
#include "generic-ops.h"
#include <boost/align/aligned_alloc.hpp>

/* Standard Cryptonight */
#define CN_PAGE_SIZE                    2097152
constexpr size_t CRYPTONIGHT_MEMORY     = 2 * 1024 * 1024;

namespace Crypto {

  extern "C" {
#include "hash-ops.h"
  }

  /*
    Cryptonight hash functions
  */

  inline void cn_fast_hash(const void *data, size_t length, Hash &hash) {
    cn_fast_hash(data, length, reinterpret_cast<char *>(&hash));
  }

  inline Hash cn_fast_hash(const void *data, size_t length) {
    Hash h;
    cn_fast_hash(data, length, reinterpret_cast<char *>(&h));
    return h;
  }

  class cn_context {
  public:

    cn_context()
    {
        long_state = (uint8_t*)boost::alignment::aligned_alloc(CRYPTONIGHT_MEMORY, CN_PAGE_SIZE);
        hash_state = (uint8_t*)boost::alignment::aligned_alloc(4096, 4096);
    }

    ~cn_context()
    {
        if(long_state != nullptr)
            boost::alignment::aligned_free(long_state);
        if(hash_state != nullptr)
            boost::alignment::aligned_free(hash_state);
    }

    cn_context(const cn_context &) = delete;
    void operator=(const cn_context &) = delete;

     uint8_t* long_state = nullptr;
     uint8_t* hash_state = nullptr;
  };

  void cn_slow_hash(cn_context &context, const void *data, size_t length, Hash &hash);
  void cn_slow_hash_gpu(cn_context &context, const void *data, size_t length, Hash &hash);
  void cn_slow_hash_krb(cn_context &context, const void *data, size_t length, Hash &hash);

  inline void tree_hash(const Hash *hashes, size_t count, Hash &root_hash) {
    tree_hash(reinterpret_cast<const char (*)[HASH_SIZE]>(hashes), count, reinterpret_cast<char *>(&root_hash));
  }

  inline void tree_branch(const Hash *hashes, size_t count, Hash *branch) {
    tree_branch(reinterpret_cast<const char (*)[HASH_SIZE]>(hashes), count, reinterpret_cast<char (*)[HASH_SIZE]>(branch));
  }

  inline void tree_hash_from_branch(const Hash *branch, size_t depth, const Hash &leaf, const void *path, Hash &root_hash) {
    tree_hash_from_branch(reinterpret_cast<const char (*)[HASH_SIZE]>(branch), depth, reinterpret_cast<const char *>(&leaf), path, reinterpret_cast<char *>(&root_hash));
  }

}

CRYPTO_MAKE_HASHABLE(Hash)
CRYPTO_MAKE_HASHABLE(EllipticCurveScalar)
CRYPTO_MAKE_HASHABLE(EllipticCurvePoint)
CRYPTO_MAKE_HASHABLE(PublicKey)
CRYPTO_MAKE_HASHABLE(SecretKey)
CRYPTO_MAKE_HASHABLE(KeyDerivation)
CRYPTO_MAKE_HASHABLE(KeyImage)

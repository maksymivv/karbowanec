// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "DBlmdb.hpp"
#include <CryptoNote.h>
#include "Difficulty.h"
#include "Serialization/ISerializer.h"
namespace Platform {
typedef DBlmdb DB;
}

namespace CryptoNote {

  const std::string version_current = "1"; // increment when making incompatible changes to indexes

  // use suffixes so all keys related to the same block are close to each other in DB
  static const std::string BLOCK_PREFIX = "b";
  static const std::string BLOCK_SUFFIX = "b";
  static const std::string TRANSACTION_PREFIX = "t";
  static const std::string TIP_CHAIN_PREFIX = "c";
  static const std::string TIMESTAMP_INDEX_PREFIX = "T";
  static const std::string TRANSACTIONS_INDEX_PREFIX = "i";
  static const std::string SPENT_KEY_IMAGES_INDEX_PREFIX = "k";
  static const std::string PAYMENT_ID_INDEX_PREFIX = "p";
  static const std::string GENERATED_TRANSACTIONS_INDEX_PREFIX = "g";
  static const std::string ORPHAN_BLOCK_INDEX_PREFIX = "o";


  struct TransactionEntry {
    Transaction tx;
    std::vector<uint32_t> m_global_output_indexes;

    void serialize(ISerializer& s) {
      s(tx, "tx");
      s(m_global_output_indexes, "indexes");
    }
  };

  struct BlockEntry {
    Block bl;
    uint32_t height;
    uint64_t block_cumulative_size;
    difficulty_type cumulative_difficulty;
    uint64_t already_generated_coins;
    std::vector<TransactionEntry> transactions;

    void serialize(ISerializer& s) {
      s(bl, "block");
      s(height, "height");
      s(block_cumulative_size, "block_cumulative_size");
      s(cumulative_difficulty, "cumulative_difficulty");
      s(already_generated_coins, "already_generated_coins");
      s(transactions, "transactions");
    }
  };

}
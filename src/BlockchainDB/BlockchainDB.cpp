// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <boost/range/adaptor/reversed.hpp>

#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/Blockchain.h"
#include "BlockchainDB/BlobDataType.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include <iostream>

#include "BlockchainDB.h"
#include "BlockchainDB/Lmdb/db_lmdb.h"

using Common::podToHex;

static const char *db_types[] = {
  "lmdb", NULL
};

namespace CryptoNote {

BlockchainDB* new_db(const std::string& db_type)
{
  if (db_type == "lmdb")
  {
    return new BlockchainLMDB();
  }
    return NULL;
}

void BlockchainDB::pop_block()
{
  CryptoNote::Block blk;
  std::vector<CryptoNote::Transaction> txs;
  pop_block(blk, txs);
}

void BlockchainDB::add_transaction(const Crypto::Hash& blk_hash, const CryptoNote::Transaction& tx, const Crypto::Hash* tx_hash_ptr)
{
  bool miner_tx = false;
  Crypto::Hash tx_hash;
  if (!tx_hash_ptr)
  {
    // should only need to compute hash for miner Transactions
    tx_hash = getObjectHash(tx);
    //Logger(INFO, Logging::BRIGHT_GREEN) << "null tx_hash_ptr - needed to compute: " << tx_hash;
  }
  else
  {
    tx_hash = *tx_hash_ptr;
  }
    std::vector<uint64_t> amount_output_indices;

        for (uint16_t o = 0; o < tx.outputs.size(); o++) {
          const auto& out = tx.outputs[o];
          if (out.target.type() == typeid(KeyOutput)) {
            amount_output_indices.push_back(add_output(tx_hash, out, o, tx.unlockTime));
          } else if (out.target.type() == typeid(MultisignatureOutput)) {
            amount_output_indices.push_back(add_output(tx_hash, out, o, tx.unlockTime));
          }
        }
        for (auto& in : tx.inputs) {
          if (in.type() == typeid(KeyInput)) {
            add_spent_key(::boost::get<KeyInput>(in).keyImage);
          } else if (in.type() == typeid(MultisignatureInput)) {
//           ::boost::get<MultisignatureInput>(in).isUsed = true;
          } else if (in.type() == typeid(CryptoNote::BaseInput)) {
            miner_tx = true;
            /* in_gen */
          }
        }

  uint64_t tx_id = add_transaction_data(blk_hash, tx, tx_hash);

  add_tx_amount_output_indices(tx_id, amount_output_indices);
}

uint64_t BlockchainDB::add_block( const CryptoNote::Block& blk
                                , const size_t& block_size
                                , const CryptoNote::difficulty_type& cumulative_difficulty
                                , const uint64_t& coins_generated
                                , const std::vector<CryptoNote::Transaction>& txs
                                )
{
  // sanity
/*  if (blk.transactionHashes.size() != txs.size())
    throw std::runtime_error("Inconsistent tx/hashes sizes");*/

  block_txn_start(false);

  Crypto::Hash blk_hash = get_block_hash(blk);

  uint64_t prev_height = height();

  // call out to add the transactions

  add_transaction(blk_hash, blk.baseTransaction);
  int tx_i = 0;
  Crypto::Hash m_hash = CryptoNote::NULL_HASH;
  for (const auto& tx : txs)
  {
    m_hash = blk.transactionHashes[tx_i];
    const Crypto::Hash tx_hash = m_hash;
    add_transaction(blk_hash, tx, &tx_hash);
    ++tx_i;
  }

  // call out to subclass implementation to add the block & metadata
  add_block(blk, block_size, cumulative_difficulty, coins_generated, blk_hash);

  m_hardfork->add(blk, prev_height);

  block_txn_stop();

  ++num_calls;

  return prev_height;
}

void BlockchainDB::set_hard_fork(HardFork* hf)
{
  m_hardfork = hf;
}

void BlockchainDB::pop_block(CryptoNote::Block& blk, std::vector<CryptoNote::Transaction>& txs)
{
  blk = get_top_block();

  remove_block();

  for (const auto& h : boost::adaptors::reverse(blk.transactionHashes))
  {
    txs.push_back(get_tx(h));
    remove_transaction(h);
  }
  remove_transaction(getObjectHash(blk.baseTransaction));
}

bool BlockchainDB::is_open() const
{
  return m_open;
}

void BlockchainDB::remove_transaction(const Crypto::Hash& tx_hash)
{
  CryptoNote::Transaction tx = get_tx(tx_hash);

  for (const CryptoNote::TransactionInput& tx_input : tx.inputs)
  {
    if (tx_input.type() == typeid(CryptoNote::KeyInput))
    {
      remove_spent_key(boost::get<CryptoNote::KeyInput>(tx_input).keyImage);
    }
  }

  // need tx as tx.vout has the tx outputs, and the output amounts are needed
  remove_transaction_data(tx_hash, tx);
}

CryptoNote::Block BlockchainDB::get_block_from_height(const uint64_t& height) const
{
  CryptoNote::blobdata bd = get_block_blob_from_height(height);
  CryptoNote::Block b;
  if (!parse_and_validate_block_from_blob(bd, b))
    throw(DB_ERROR("Failed to parse block from blob retrieved from the db"));

  return b;
}

CryptoNote::Block BlockchainDB::get_block(const Crypto::Hash& h) const
{
  CryptoNote::blobdata bd = get_block_blob(h);
  CryptoNote::Block b;
  if (!parse_and_validate_block_from_blob(bd, b))
    throw(DB_ERROR("Failed to parse block from blob retrieved from the db"));

  return b;
}

bool BlockchainDB::get_tx(const Crypto::Hash& h, CryptoNote::Transaction &tx) const
{
  CryptoNote::blobdata bd;
  if (!get_tx_blob(h, bd))
    return false;
  if (!parse_and_validate_tx_from_blob(bd, tx))
    throw(DB_ERROR("Failed to parse transaction from blob retrieved from the db"));

  return true;
}

CryptoNote::Transaction BlockchainDB::get_tx(const Crypto::Hash& h) const
{
  CryptoNote::Transaction tx;
  if (!get_tx(h, tx))
    throw(TX_DNE(std::string("tx with hash ").append(Common::podToHex(h)).append(" not found in db").c_str()));
  return tx;
}

void BlockchainDB::fixup()
{
  if (is_read_only()) {
    //Logger(INFO, WHITE) << "Database is opened read only - skipping fixup check";
    return;
  }

  set_batch_transactions(true);
  batch_start();
  batch_stop();
}

} //namespace CryptoNote


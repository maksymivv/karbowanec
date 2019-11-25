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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <string>
#include <vector>
#include <map>

#include "BlockchainDB.h"
#include "Structures.h"

namespace CryptoNote
{

class BaseTestDB: public CryptoNote::BlockchainDB {
public:
  BaseTestDB() {}
  virtual void open(const std::string& filename, const int db_flags = 0) override { }
  virtual void close() override {}
  virtual void sync() override {}
  virtual void safesyncmode(const bool onoff) override {}
  virtual void reset() override {}
  virtual std::vector<std::string> get_filenames() const override { return std::vector<std::string>(); }
  virtual bool remove_data_file(const std::string& folder) const { return true; }
  virtual std::string get_db_name() const override { return std::string(); }
  virtual bool lock() override { return true; }
  virtual void unlock() override { }
  virtual bool batch_start(uint64_t batch_num_blocks=0, uint64_t batch_bytes=0) override { return true; }
  virtual void batch_stop() override {}
  virtual void set_batch_transactions(bool) override {}
  virtual void block_wtxn_start() {}
  virtual void block_wtxn_stop() {}
  virtual void block_wtxn_abort() {}
  virtual bool block_rtxn_start() const { return true; }
  virtual void block_rtxn_stop() const {}
  virtual void block_rtxn_abort() const {}

  virtual bool block_exists(const Crypto::Hash& h, uint64_t *height) const override { return false; }
 // virtual CryptoNote::blobdata get_block_blob_from_height(const uint64_t& height) const override { return CryptoNote::t_serializable_object_to_blob(get_block_from_height(height)); }
  virtual CryptoNote::blobdata get_block_blob(const Crypto::Hash& h) const override { return CryptoNote::blobdata(); }
  virtual bool get_tx_blob(const Crypto::Hash& h, CryptoNote::blobdata &tx) const override { return false; }
  virtual uint64_t get_block_height(const Crypto::Hash& h) const override { return 0; }
  virtual CryptoNote::BlockHeader get_block_header(const Crypto::Hash& h) const override { return CryptoNote::BlockHeader(); }
  virtual uint64_t get_block_timestamp(const uint64_t& height) const override { return 0; }
  virtual uint64_t get_top_block_timestamp() const override { return 0; }
  virtual size_t get_block_size(const uint64_t& height) const override { return 128; }
  virtual std::vector<uint64_t> get_block_sizes(uint64_t start_height, size_t count) const { return {}; }
  virtual CryptoNote::difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const override { return 10; }
  virtual CryptoNote::difficulty_type get_block_difficulty(const uint64_t& height) const override { return 0; }
  virtual uint64_t get_block_already_generated_coins(const uint64_t& height) const override { return 10000000000; }
  virtual Crypto::Hash get_block_hash_from_height(const uint64_t& height) const override { return Crypto::Hash(); }
  virtual std::vector<CryptoNote::Block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) const override { return std::vector<CryptoNote::Block>(); }
  virtual std::vector<Crypto::Hash> get_hashes_range(const uint64_t& h1, const uint64_t& h2) const override { return std::vector<Crypto::Hash>(); }
  virtual Crypto::Hash top_block_hash(uint64_t *block_height = NULL) const { if (block_height) *block_height = 0; return Crypto::Hash(); }
  virtual CryptoNote::Block get_top_block() const override { return CryptoNote::Block(); }
  virtual uint64_t height() const override { return 1; }
  virtual bool tx_exists(const Crypto::Hash& h) const override { return false; }
  virtual bool tx_exists(const Crypto::Hash& h, uint64_t& tx_index) const override { return false; }
  virtual uint64_t get_tx_unlock_time(const Crypto::Hash& h) const override { return 0; }
  virtual CryptoNote::Transaction get_tx(const Crypto::Hash& h) const override { return CryptoNote::Transaction(); }
  virtual bool get_tx(const Crypto::Hash& h, CryptoNote::Transaction &tx) const override { return false; }
  virtual uint64_t get_tx_count() const override { return 0; }
  virtual std::vector<CryptoNote::Transaction> get_tx_list(const std::vector<Crypto::Hash>& hlist) const override { return std::vector<CryptoNote::Transaction>(); }
  virtual uint64_t get_tx_block_height(const Crypto::Hash& h) const override { return 0; }
  virtual uint64_t get_num_outputs(const uint64_t& amount) const override { return 1; }
  virtual uint64_t get_indexing_base() const override { return 0; }
  virtual CryptoNote::tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const override { return CryptoNote::tx_out_index(); }
  virtual CryptoNote::tx_out_index get_output_tx_and_index(const uint64_t& amount, const uint64_t& index) const override { return CryptoNote::tx_out_index(); }
  virtual void get_output_tx_and_index(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<CryptoNote::tx_out_index> &indices) const override {}
  virtual bool can_thread_bulk_indices() const override { return false; }
  virtual bool has_key_image(const Crypto::KeyImage& img) const override { return false; }
  virtual void remove_block() override { }
//  virtual uint64_t add_transaction_data(const Crypto::Hash& blk_hash, const std::pair<CryptoNote::Transaction, CryptoNote::BinaryArray>& tx, const Crypto::Hash& tx_hash, const Crypto::Hash& tx_prunable_hash) override {return 0;}
//  virtual void remove_transaction_data(const Crypto::Hash& tx_hash, const CryptoNote::Transaction& tx) override {}
  virtual uint64_t add_output(const Crypto::Hash& tx_hash, const CryptoNote::TransactionOutput& tx_output, const uint64_t& local_index, const uint64_t unlock_time) override {return 0;}
  virtual void add_tx_amount_output_indices(const uint64_t tx_index, const std::vector<uint64_t>& amount_output_indices) override {}
  virtual void add_spent_key(const Crypto::KeyImage& k_image) override {}
  virtual void remove_spent_key(const Crypto::KeyImage& k_image) override {}

  virtual bool for_all_key_images(std::function<bool(const Crypto::KeyImage&)>) const override { return true; }
  virtual bool for_blocks_range(const uint64_t&, const uint64_t&, std::function<bool(uint64_t, const Crypto::Hash&, const CryptoNote::Block&)>) const override { return true; }
  virtual bool for_all_transactions(std::function<bool(const Crypto::Hash&, const CryptoNote::Transaction&)>) const override { return true; }
  virtual bool for_all_outputs(std::function<bool(uint64_t amount, const Crypto::Hash &tx_hash, uint64_t height, size_t tx_idx)> f) const override { return true; }
  virtual bool for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f) const override { return true; }
  virtual bool is_read_only() const override { return false; }
//  virtual std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, uint64_t min_count) const override { return std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>>(); }
//  virtual bool get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, std::vector<uint64_t> &distribution, uint64_t &base) const { return false; }

  virtual void add_txpool_tx(const Crypto::Hash &txid, const CryptoNote::BinaryArray &blob, const CryptoNote::txpool_tx_meta_t& details) {}
  virtual void update_txpool_tx(const Crypto::Hash &txid, const CryptoNote::txpool_tx_meta_t& details) override {}
  virtual uint64_t get_txpool_tx_count(bool include_unrelayed_txes = true) const override { return 0; }
  virtual bool txpool_has_tx(const Crypto::Hash &txid) const override { return false; }
  virtual void remove_txpool_tx(const Crypto::Hash& txid) override {}
  virtual bool get_txpool_tx_meta(const Crypto::Hash& txid, CryptoNote::txpool_tx_meta_t &meta) const override { return false; }
  virtual bool get_txpool_tx_blob(const Crypto::Hash& txid, CryptoNote::BinaryArray &bd) const { return false; }
  virtual uint64_t get_database_size() const { return 0; }
  virtual CryptoNote::blobdata get_txpool_tx_blob(const Crypto::Hash& txid) const override { return ""; }
  virtual bool for_all_txpool_txes(std::function<bool(const Crypto::Hash&, const CryptoNote::txpool_tx_meta_t&, const CryptoNote::BinaryArray*)>, bool include_blob = false) const { return false; }

  virtual void add_block( const CryptoNote::Block& blk
                        , size_t block_size
                        , const CryptoNote::difficulty_type& cumulative_difficulty
                        , const uint64_t& coins_generated
                        , const Crypto::Hash& blk_hash
                        ) { }
  virtual CryptoNote::Block get_block_from_height(const uint64_t& height) const override { return CryptoNote::Block(); }

};

}

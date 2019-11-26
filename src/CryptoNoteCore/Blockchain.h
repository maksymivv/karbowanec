// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018-2019, The Qwertycoin developers
// Copyright (c) 2016, The Karbowanec developers
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

#include <atomic>
#include "google/sparse_hash_set"
#include "google/sparse_hash_map"
#include <boost/asio/io_service.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/version.hpp>
#include <boost/serialization/list.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/global_fun.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/random_access_index.hpp>

#include "Common/ObserverManager.h"
#include "Common/Util.h"
#include "CryptoNoteCore/BlockIndex.h"
#include "CryptoNoteCore/Checkpoints.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/IBlockchainStorageObserver.h"
#include "CryptoNoteCore/ITransactionValidator.h"
#include "CryptoNoteCore/SwappedVector.h"
#include "CryptoNoteCore/UpgradeDetector.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/TransactionPool.h"
#include "CryptoNoteCore/BlockchainIndices.h"
#include "BlockchainDB/BlockchainDB.h"

#include "CryptoNoteCore/MessageQueue.h"
#include "CryptoNoteCore/BlockchainMessages.h"
#include "CryptoNoteCore/IntrusiveLinkedList.h"

#include <Logging/LoggerRef.h>

#undef ERROR

namespace CryptoNote {
using CryptoNote::BlockInfo;

struct NOTIFY_REQUEST_GET_OBJECTS_request;
struct NOTIFY_RESPONSE_GET_OBJECTS_request;
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request;
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response;
struct COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount;

enum blockchain_db_sync_mode
{
  db_default_sync,
  db_sync,
  db_async,
  db_nosync
};

struct block_extended_info
{
  Block bl; //!< the block
  uint64_t height; //!< the height of the block in the blockchain
  size_t block_cumulative_size; //!< the size (in bytes) of the block
  difficulty_type cumulative_difficulty; //!< the accumulated difficulty after that block
  uint64_t already_generated_coins; //!< the total coins minted after that block
};

class Blockchain : public CryptoNote::ITransactionValidator
{
public:
    Blockchain(
        std::unique_ptr<BlockchainDB>& db,
        HardFork*& hf,
        const Currency &currency,
        tx_memory_pool &tx_pool,
        Logging::ILogger &logger,
        bool blockchainIndexesEnabled
    );
    bool pushBlock(const Block& blockData, block_verification_context& bvc);
    bool pushBlock(const Block& blockData, const std::vector<Transaction>& transactions, block_verification_context& bvc);

    void set_user_options(uint64_t maxthreads, uint64_t blocks_per_sync, blockchain_db_sync_mode sync_mode, bool fast_sync);

    bool addObserver(IBlockchainStorageObserver* observer);
    bool removeObserver(IBlockchainStorageObserver* observer);

    // ITransactionValidator
    virtual bool checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock) override;
    virtual bool checkTransactionInputs(const CryptoNote::Transaction& tx, BlockInfo& maxUsedBlock, BlockInfo& lastFailed) override;
    virtual bool haveSpentKeyImages(const CryptoNote::Transaction& tx) override;
    virtual bool checkTransactionSize(size_t blobSize) override;

    bool init() { return init(Tools::getDefaultDataDirectory(), Tools::getDefaultDbType(), 0, true); }
    bool init(const std::string& config_folder, const std::string& db_type, const int& db_flags, bool load_existing);
    bool deinit();

    bool getLowerBound(uint64_t timestamp, uint64_t startOffset, uint32_t& height);
    std::vector<Crypto::Hash> getBlockIds(uint32_t startHeight, uint32_t maxCount);
    bool have_tx(const Crypto::Hash &id) const;
    bool have_tx_keyimg_as_spent(const Crypto::KeyImage &key_im) const;
    Crypto::PublicKey get_output_key(uint64_t amount, uint64_t global_index) const;
    void setCheckpoints(Checkpoints&& chk_pts) { m_checkpoints = chk_pts; }
    bool getBlocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks, std::list<Transaction>& txs);
    bool getBlocks(uint32_t start_offset, uint32_t count, std::list<Block>& blocks);
    bool getAlternativeBlocks(std::list<Block>& blocks);
    uint32_t getAlternativeBlocksCount();
    Crypto::Hash getBlockIdByHeight(uint32_t height);
    bool getBlockByHash(const Crypto::Hash &h, Block &blk);
    bool getBlockHeight(const Crypto::Hash& blockId, uint32_t& blockHeight);
    bool store_blockchain();

    template<class archive_t> void serialize(archive_t & ar, const unsigned int version);

    bool haveTransaction(const Crypto::Hash &id);
    bool haveTransactionKeyImagesAsSpent(const Transaction &tx);

    uint32_t getCurrentBlockchainHeight(); //TODO rename to getCurrentBlockchainSize
    Crypto::Hash getTailId();
    Crypto::Hash getTailId(uint32_t& height);
    difficulty_type getDifficultyForNextBlock();
    uint64_t getBlockTimestamp(uint32_t height);
    uint64_t getMinimalFee(uint32_t height);
    uint64_t getCoinsInCirculation();
    uint8_t getBlockMajorVersionForHeight(uint32_t height) const;
    bool addNewBlock(const Block& bl, block_verification_context& bvc);
    bool add_new_block(const Block& b, block_verification_context& bvc);
    bool cleanup_handle_incoming_blocks(bool force_sync);
    bool prepare_handle_incoming_blocks(const std::vector<block_complete_entry> &blocks_entry);
    bool resetAndSetGenesisBlock(const Block& b);
    bool haveBlock(const Crypto::Hash& id);
    size_t getTotalTransactions();
    std::vector<Crypto::Hash> buildSparseChain();
    std::vector<Crypto::Hash> buildSparseChain(const Crypto::Hash& startBlockId);
    uint32_t findBlockchainSupplement(const std::vector<Crypto::Hash>& qblock_ids); // !!!!
    std::vector<Crypto::Hash> findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds, size_t maxCount,
      uint32_t& totalBlockCount, uint32_t& startBlockIndex);
    bool handleGetObjects(NOTIFY_REQUEST_GET_OBJECTS_request& arg, NOTIFY_RESPONSE_GET_OBJECTS_request& rsp); //Deprecated. Should be removed with CryptoNoteProtocolHandler.
    bool getRandomOutsByAmount(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_request& req, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_response& res);
    bool getBackwardBlocksSize(size_t from_height, std::vector<size_t>& sz, size_t count);
    bool getTransactionOutputGlobalIndexes(const Crypto::Hash& tx_id, std::vector<uint32_t>& indexs);
    bool get_out_by_msig_gindex(uint64_t amount, uint64_t gindex, MultisignatureOutput& out);
    bool checkTransactionInputs(const Transaction& tx, uint32_t& pmax_used_block_height, Crypto::Hash& max_used_block_id, BlockInfo* tail = 0);
    template<class visitor_t>
    inline bool scan_outputkeys_for_indexes(const KeyInput& tx_in_to_key, visitor_t &vis, const Crypto::Hash &tx_prefix_hash, uint32_t* pmax_related_block_height) const;

    uint64_t getCurrentCumulativeBlocksizeLimit();
    uint64_t blockDifficulty(size_t i);
    uint64_t blockCumulativeDifficulty(size_t i);
    bool getBlockContainingTransaction(const Crypto::Hash& txId, Crypto::Hash& blockId, uint32_t& blockHeight);
    bool getAlreadyGeneratedCoins(const Crypto::Hash& hash, uint64_t& generatedCoins);
    bool getBlockSize(const Crypto::Hash& hash, size_t& size);
    bool getMultisigOutputReference(const MultisignatureInput& txInMultisig, std::pair<Crypto::Hash, size_t>& outputReference);
    bool getGeneratedTransactionsNumber(uint32_t height, uint64_t& generatedTransactions);
    bool getOrphanBlockIdsByHeight(uint32_t height, std::vector<Crypto::Hash>& blockHashes);
    bool getBlockIdsByTimestamp(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t blocksNumberLimit, std::vector<Crypto::Hash>& hashes, uint32_t& blocksNumberWithinTimestamps);
    bool getTransactionIdsByPaymentId(const Crypto::Hash& paymentId, std::vector<Crypto::Hash>& transactionHashes);
    bool isBlockInMainChain(const Crypto::Hash& blockId);
    bool isInCheckpointZone(const uint32_t height);
    uint64_t getAvgDifficultyForHeight(uint32_t height, uint32_t window);

    template<class visitor_t> bool scanOutputKeysForIndexes(const KeyInput& tx_in_to_key, visitor_t& vis, uint32_t* pmax_related_block_height = NULL);

    bool addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue);
    bool removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue);
    bool find_blockchain_supplement(const std::vector<Crypto::Hash>& qblock_ids, size_t& starter_offset);
    bool find_blockchain_supplement(const std::vector<Crypto::Hash>& qblock_ids, std::vector<Crypto::Hash>& hashes, size_t& start_height, size_t& current_height);
    bool find_blockchain_supplement(const std::vector<Crypto::Hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp);
    bool find_blockchain_supplement(const uint64_t req_start_block, const std::vector<Crypto::Hash>& qblock_ids, std::vector<std::pair<CryptoNote::blobdata, std::vector<CryptoNote::blobdata> > >& blocks, size_t& total_height, size_t& start_height, size_t max_count);
    bool add_block_as_invalid(const Block& bl, const Crypto::Hash& h);
    bool add_block_as_invalid(block_extended_info& bei, const Crypto::Hash& h);
    void add_txpool_tx(Transaction &tx, const txpool_tx_meta_t &meta);
    void update_txpool_tx(const Crypto::Hash &txid, const txpool_tx_meta_t &meta);
    void remove_txpool_tx(const Crypto::Hash &txid);
    uint64_t get_txpool_tx_count() const;
    bool get_txpool_tx_meta(const Crypto::Hash& txid, txpool_tx_meta_t &meta) const;
    bool get_txpool_tx_blob(const Crypto::Hash& txid, CryptoNote::blobdata &bd) const;
    void get_txpool_tx_blobs(std::list<Crypto::Hash> hashes, std::list<blobdata>& txs);
    CryptoNote::blobdata get_txpool_tx_blob(const Crypto::Hash& txid) const;
    bool for_all_txpool_txes(std::function<bool(const Crypto::Hash&, const txpool_tx_meta_t&, const CryptoNote::blobdata*)>, bool include_blob = false) const;
    bool for_all_outputs(std::function<bool(uint64_t amount, const Crypto::Hash &tx_hash, uint64_t height, size_t tx_idx)> f) const;


    template<class t_ids_container, class t_blocks_container, class t_missed_container>
    bool getBlocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs) {
      std::lock_guard<std::recursive_mutex> lk(m_blockchain_lock);

      for (const auto& bl_id : block_ids) {
        try {
          uint32_t height = 0;
          if (!m_blockIndex.getBlockHeight(bl_id, height)) {
            missed_bs.push_back(bl_id);
          } else {
            if (Tools::getDefaultDbType() != "lmdb") {
              if (!(height < m_blocks.size())) { logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: bl_id=" << Common::podToHex(bl_id)
              << " have index record with offset=" << height << ", bigger then m_blocks.size()=" << m_blocks.size(); return false; }
              blocks.push_back(m_blocks[height].bl);
            } else {
              if (!(height < m_db->height())) { logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: bl_id=" << Common::podToHex(bl_id)
              << " have index record with offset=" << height << ", larger then m_db->height()=" << m_db->height(); return false; }
              blocks.push_back(m_db->get_block_from_height(height));
            }
          }
        } catch (const std::exception& e) {
          logger(Logging::ERROR, Logging::BRIGHT_RED) << "Exception in Core getBlocks: " << e.what();
          return false;
        }
      }
      return true;
    }
    template<class t_ids_container, class t_tx_container, class t_missed_container>
    void get_transactions_blobs(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs);
    template<class t_ids_container, class t_tx_container, class t_missed_container>
    void get_transactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs);

    template<class t_ids_container, class t_tx_container, class t_missed_container>
    void getBlockchainTransactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs) {
      std::lock_guard<decltype(m_blockchain_lock)> bcLock(m_blockchain_lock);

      for (const auto& tx_id : txs_ids) {
        auto it = m_transactionMap.find(tx_id);
        if (it == m_transactionMap.end()) {
          missed_txs.push_back(tx_id);
        } else {
          txs.push_back(transactionByIndex(it->second).tx);
        }
      }
    }

    template<class t_ids_container, class t_tx_container, class t_missed_container>
    void getTransactions(const t_ids_container& txs_ids, t_tx_container& txs, t_missed_container& missed_txs, bool checkTxPool = false) {
      Tools::getDefaultDbType() != "lmdb";
      if (checkTxPool){
        std::lock_guard<decltype(m_tx_pool)> txLock(m_tx_pool);

        getBlockchainTransactions(txs_ids, txs, missed_txs);

        auto poolTxIds = std::move(missed_txs);
        missed_txs.clear();
        m_tx_pool.getTransactions(poolTxIds, txs, missed_txs);

      } else {
        getBlockchainTransactions(txs_ids, txs, missed_txs);
      }
    }

    //debug functions
    void print_blockchain(uint64_t start_index, uint64_t end_index);
    void print_blockchain_index();
    void print_blockchain_outs(const std::string& file);

    struct TransactionIndex {
      uint32_t block;
      uint16_t transaction;

      void serialize(ISerializer& s) {
        s(block, "block");
        s(transaction, "tx");
      }
    };

    struct SpentKeyImage {
      uint32_t blockIndex;
      Crypto::KeyImage keyImage;

      void serialize(ISerializer& s) {
        s(blockIndex, "block_index");
        s(keyImage, "key_image");
      }
    };

    void rollbackBlockchainTo(uint32_t height);
    bool have_tx_keyimg_as_spent(const Crypto::KeyImage &key_im);
    bool checkIfSpent(const Crypto::KeyImage& keyImage, uint32_t blockIndex);
    bool checkIfSpent(const Crypto::KeyImage& keyImage);
    bool is_tx_spendtime_unlocked(uint64_t unlock_time);
    bool is_tx_spendtime_unlocked(uint64_t unlock_time, uint32_t height);
    void safesyncmode(const bool onoff);

    BlockchainDB* m_db;
    uint64_t m_sync_counter;
    uint64_t m_db_blocks_per_sync;

    const BlockchainDB& get_db() const
    {
      return *m_db;
    }

    BlockchainDB& get_db()
    {
      return *m_db;
    }

private:

    struct MultisignatureOutputUsage {
      TransactionIndex transactionIndex;
      uint16_t outputIndex;
      bool isUsed;

      void serialize(ISerializer& s) {
        s(transactionIndex, "txindex");
        s(outputIndex, "outindex");
        s(isUsed, "used");
      }
    };

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

    struct BlockIndexTag {};
    struct KeyImageTag {};

    typedef boost::multi_index_container<
      SpentKeyImage,
      boost::multi_index::indexed_by<
      boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<BlockIndexTag>,
      BOOST_MULTI_INDEX_MEMBER(SpentKeyImage, uint32_t, blockIndex)
      >,
      boost::multi_index::hashed_unique<
      boost::multi_index::tag<KeyImageTag>,
      BOOST_MULTI_INDEX_MEMBER(SpentKeyImage, Crypto::KeyImage, keyImage)
      >
      >
    > SpentKeyImagesContainer;
    union _bex { block_extended_info* info; BlockEntry* entry; };
    typedef union _bex bex;
    typedef std::unordered_map<Crypto::Hash, BlockEntry> blocks_ext_by_hash;
    typedef std::unordered_map<Crypto::Hash, bex> bex_by_hash;
    bex_by_hash m_invalid_blocks;
    typedef google::sparse_hash_map<uint64_t, std::vector<std::pair<TransactionIndex, uint16_t>>> outputs_container; //Crypto::Hash - tx hash, size_t - index of out in transaction
    typedef google::sparse_hash_map<uint64_t, std::vector<MultisignatureOutputUsage>> MultisignatureOutputsContainer;
    blockchain_db_sync_mode m_db_sync_mode;

    const Currency& m_currency;
    tx_memory_pool& m_tx_pool;
    std::recursive_mutex m_blockchain_lock; // TODO: add here reader/writer lock
    Crypto::cn_context m_cn_context;
    Tools::ObserverManager<IBlockchainStorageObserver> m_observerManager;

    SpentKeyImagesContainer spentKeyImages;
    size_t m_current_block_cumul_sz_limit;
    blocks_ext_by_hash m_alternative_chains; // Crypto::Hash -> block_extended_info
    outputs_container m_outputs;

    std::string m_config_folder;
    Checkpoints m_checkpoints;
    std::atomic<bool> m_is_in_checkpoint_zone;

    typedef SwappedVector<BlockEntry> Blocks;
    typedef SwappedVector<block_extended_info> blocks;
    typedef std::unordered_map<Crypto::Hash, uint32_t> BlockMap;
    typedef std::unordered_map<Crypto::Hash, TransactionIndex> TransactionMap;
    typedef BasicUpgradeDetector<Blocks> UpgradeDetector;
    UpgradeDetector m_upgradeDetectorV2;
    UpgradeDetector m_upgradeDetectorV3;
    UpgradeDetector m_upgradeDetectorV4;
    UpgradeDetector m_upgradeDetectorV5;
    friend class BlockCacheSerializer;
    friend class BlockchainIndicesSerializer;
    HardFork *m_hardfork;
    std::atomic<bool> m_cancel;

    boost::asio::io_service m_async_service;
    boost::thread_group m_async_pool;
    std::unique_ptr<boost::asio::io_service::work> m_async_work_idle;
    Blocks m_blocks;
    CryptoNote::BlockIndex m_blockIndex;
    TransactionMap m_transactionMap;
    MultisignatureOutputsContainer m_multisignatureOutputs;


    PaymentIdIndex m_paymentIdIndex;
    TimestampBlocksIndex m_timestampIndex;
    GeneratedTransactionsIndex m_generatedTransactionsIndex;
    OrphanBlocksIndex m_orphanBlocksIndex;
    bool m_blockchainIndexesEnabled;
    void cancel();
    std::unordered_map<Crypto::Hash, std::unordered_map<Crypto::KeyImage, std::vector<output_data_t>>> m_scan_table;
    std::unordered_map<Crypto::Hash, Crypto::Hash> m_blocks_longhash_table;
    std::unordered_map<Crypto::Hash, std::unordered_map<Crypto::KeyImage, bool>> m_check_txin_table;

    IntrusiveLinkedList<MessageQueue<BlockchainMessage>> m_messageQueueList;

    Logging::LoggerRef logger;

    void rebuildCache();
    bool storeCache();
    bool switch_to_alternative_blockchain(std::list<blocks_ext_by_hash::iterator>& alt_chain, bool discard_disconnected_chain);
    bool handle_alternative_block(const Block& b, const Crypto::Hash& id, block_verification_context& bvc, bool sendNewAlternativeBlockMessage = true);
    difficulty_type get_next_difficulty_for_alternative_chain(const std::list<blocks_ext_by_hash::iterator>& alt_chain, BlockEntry& bei);
    bool prevalidate_miner_transaction(const Block& b, uint32_t height);
    bool validate_miner_transaction(const Block& b, uint32_t height, size_t cumulativeBlockSize, uint64_t alreadyGeneratedCoins, uint64_t fee, uint64_t& reward, int64_t& emissionChange);
    bool rollback_blockchain_switching(std::list<Block>& original_chain, size_t rollback_height);
    bool get_last_n_blocks_sizes(std::vector<size_t>& sz, size_t count);
    bool add_out_to_get_random_outs(std::vector<std::pair<TransactionIndex, uint16_t>>& amount_outs, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS_outs_for_amount& result_outs, uint64_t amount, size_t i);
    size_t find_end_of_allowed_index(const std::vector<std::pair<TransactionIndex, uint16_t>>& amount_outs);
    bool check_block_timestamp_main(const Block& b);
    bool check_block_timestamp(std::vector<uint64_t> timestamps, const Block& b);
    uint64_t get_adjusted_time();
	bool complete_timestamps_vector(uint8_t blockMajorVersion, uint64_t start_height, std::vector<uint64_t>& timestamps);
    bool checkBlockVersion(const Block& b, const Crypto::Hash& blockHash);
    bool checkParentBlockSize(const Block& b, const Crypto::Hash& blockHash);
    bool checkCumulativeBlockSize(const Crypto::Hash& blockId, size_t cumulativeBlockSize, uint64_t height);
    std::vector<Crypto::Hash> doBuildSparseChain(const Crypto::Hash& startBlockId) const;
    bool getBlockCumulativeSize(const Block& block, size_t& cumulativeSize);
    bool update_next_cumulative_size_limit();
    bool check_tx_input(const KeyInput& txin, const Crypto::Hash& tx_prefix_hash, const std::vector<Crypto::Signature>& sig, uint32_t* pmax_related_block_height = NULL);
    bool checkTransactionInputs(const Transaction& tx, const Crypto::Hash& tx_prefix_hash, uint32_t* pmax_used_block_height = NULL);
    bool checkTransactionInputs(const Transaction& tx, uint32_t* pmax_used_block_height = NULL);
    const TransactionEntry& transactionByIndex(TransactionIndex index);
    bool pushBlock(BlockEntry& block);
    void popBlock();
    bool pushTransaction(BlockEntry& block, const Crypto::Hash& transactionHash, TransactionIndex transactionIndex);
    void popTransaction(const Transaction& transaction, const Crypto::Hash& transactionHash);
    void popTransactions(const BlockEntry& block, const Crypto::Hash& minerTransactionHash);
    void popTransactions(const Block& block, const Crypto::Hash& minerTransactionHash);
    bool validateInput(const MultisignatureInput& input, const Crypto::Hash& transactionHash, const Crypto::Hash& transactionPrefixHash, const std::vector<Crypto::Signature>& transactionSignatures);
    bool checkCheckpoints(uint32_t& lastValidCheckpointHeight);
    void removeLastBlock();
    bool checkUpgradeHeight(const UpgradeDetector& upgradeDetector);
    bool m_db_default_sync;
    void get_txpool_txs(std::list<Transaction>& txs);
    std::string filename_mdb;
    int flags_mdb;
    bool handle_block_to_main_chain(const Block& bl, const Crypto::Hash& id, block_verification_context& bvc);
    HardFork::State get_hard_fork_state() const;
    void output_scan_worker(const uint64_t amount,const std::vector<uint32_t> &offsets,
        std::vector<output_data_t> &outputs, std::unordered_map<Crypto::Hash,
        CryptoNote::Transaction> &txs) const;
    void block_longhash_worker(uint64_t height, const std::vector<CryptoNote::Block> &blocks,
        std::unordered_map<Crypto::Hash, Crypto::Hash> &map) const;
    std::vector<Crypto::Hash> m_blocks_hash_check;
    std::vector<Crypto::Hash> m_blocks_txs_check;

    bool storeBlockchainIndices();
    bool loadBlockchainIndices();

    bool loadTransactions(const Block& block, std::vector<Transaction>& transactions);
    void saveTransactions(const std::vector<Transaction>& transactions);
    //bool check_for_double_spend(const Transaction& tx, key_images_container& keys_this_block) const;

    void sendMessage(const BlockchainMessage& message);

    friend class LockedBlockchainStorage;
  };

  class LockedBlockchainStorage: boost::noncopyable {
  public:

    LockedBlockchainStorage(Blockchain& bc)
      : m_bc(bc), m_lock(bc.m_blockchain_lock) {}

    Blockchain* operator -> () {
      return &m_bc;
    }

  private:

    Blockchain& m_bc;
    std::lock_guard<std::recursive_mutex> m_lock;
  };

  template<class visitor_t> bool Blockchain::scanOutputKeysForIndexes(const KeyInput& tx_in_to_key, visitor_t& vis, uint32_t* pmax_related_block_height) {
    std::lock_guard<std::recursive_mutex> lk(m_blockchain_lock);
    auto it = m_outputs.find(tx_in_to_key.amount);
    if (it == m_outputs.end() || !tx_in_to_key.outputIndexes.size())
      return false;

    std::vector<uint32_t> absolute_offsets = relative_output_offsets_to_absolute(tx_in_to_key.outputIndexes);
    std::vector<std::pair<TransactionIndex, uint16_t>>& amount_outs_vec = it->second;
    size_t count = 0;
    for (uint64_t i : absolute_offsets) {
      if(i >= amount_outs_vec.size() ) {
        logger(Logging::INFO) << "Wrong index in transaction inputs: " << i << ", expected maximum " << amount_outs_vec.size() - 1;
        return false;
      }

      //auto tx_it = m_transactionMap.find(amount_outs_vec[i].first);
      //if (!(tx_it != m_transactionMap.end())) { logger(ERROR, BRIGHT_RED) << "Wrong transaction id in output indexes: " << Common::podToHex(amount_outs_vec[i].first); return false; }

      const TransactionEntry& tx = transactionByIndex(amount_outs_vec[i].first);

      if (!(amount_outs_vec[i].second < tx.tx.outputs.size())) {
        logger(Logging::ERROR, Logging::BRIGHT_RED)
            << "Wrong index in transaction outputs: "
            << amount_outs_vec[i].second << ", expected less then "
            << tx.tx.outputs.size();
        return false;
      }

      if (!vis.handle_output(tx.tx, tx.tx.outputs[amount_outs_vec[i].second], amount_outs_vec[i].second)) {
        logger(Logging::INFO) << "Failed to handle_output for output no = " << count << ", with absolute offset " << i;
        return false;
      }

      if(count++ == absolute_offsets.size()-1 && pmax_related_block_height) {
        if (*pmax_related_block_height < amount_outs_vec[i].first.block) {
          *pmax_related_block_height = amount_outs_vec[i].first.block;
        }
      }
    }

    return true;
  }
}


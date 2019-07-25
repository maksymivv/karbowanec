// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2016-2019, The Karbo developers
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

#include "Miner.h"

#include <future>
#include <numeric>
#include <sstream>
#include <thread>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/filesystem.hpp>
#include <boost/limits.hpp>
#include <boost/utility/value_init.hpp>

#include "../CryptoNoteConfig.h"

#include "crypto/crypto.h"
#include "Common/CommandLine.h"
#include "Common/Math.h"
#include "Common/StringTools.h"
#include "Serialization/SerializationTools.h"

#include "CryptoNoteTools.h"
#include "CryptoNoteFormatUtils.h"
#include "TransactionExtra.h"

#include "Wallet/WalletRpcServerCommandsDefinitions.h"

using namespace Logging;

namespace CryptoNote
{

  miner::miner(const Currency& currency, IMinerHandler& handler, Logging::ILogger& log, System::Dispatcher& dispatcher) :
    m_currency(currency),
    m_dispatcher(dispatcher),
    logger(log, "miner"),
    m_stop(true),
    m_template(boost::value_initialized<Block>()),
    m_template_no(0),
    m_diffic(0),
    m_handler(handler),
    m_pausers_count(0),
    m_threads_total(0),
    m_starter_nonce(0),
    m_last_hr_merge_time(0),
    m_hashes(0),
    m_do_print_hashrate(true),
    m_do_mining(false),
    m_current_hash_rate(0),
    m_update_block_template_interval(15),
    m_update_merge_hr_interval(2)
  {
  }
  //-----------------------------------------------------------------------------------------------------
  miner::~miner() {
    stop();
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_block_template(const Block& bl, const difficulty_type& di) {
    std::lock_guard<decltype(m_template_lock)> lk(m_template_lock);

    m_template = bl;

    if (m_template.majorVersion == BLOCK_MAJOR_VERSION_2 || m_template.majorVersion == BLOCK_MAJOR_VERSION_3) {
      CryptoNote::TransactionExtraMergeMiningTag mm_tag;
      mm_tag.depth = 0;
      if (!CryptoNote::get_aux_block_header_hash(m_template, mm_tag.merkleRoot)) {
        return false;
      }

      m_template.parentBlock.baseTransaction.extra.clear();
      if (!CryptoNote::appendMergeMiningTagToExtra(m_template.parentBlock.baseTransaction.extra, mm_tag)) {
        return false;
      }
    }

    m_diffic = di;
    ++m_template_no;
    m_starter_nonce = Crypto::rand<uint32_t>();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_block_chain_update() {
    if (!is_mining()) {
      return true;
    }

    return request_block_template(true, true);
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::requestStakeTransaction(uint64_t& reward, uint64_t& fee, uint32_t& height, CryptoNote::BinaryArray& extra_nonce, bool wait_wallet_refresh, bool local_dispatcher, Transaction& transaction) {
    uint64_t nextDifficulty = m_handler.getNextBlockDifficulty();

    logger(INFO) << "Requesting stake deposit transaction for height " << height << " at difficulty " << nextDifficulty;

    // Calculate stake
    uint64_t alreadyGeneratedCoins = m_handler.getTotalGeneratedAmount();
    uint64_t firstReward = UINT64_C(38146972656250); // just use constant not to query it from blockchain
    uint64_t baseReward = reward - fee; // exclude fees
    uint64_t baseStake = alreadyGeneratedCoins / CryptoNote::parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V1 / 4 / firstReward * baseReward;

    logger(INFO) << "Base Stake: " << m_currency.formatAmount(baseStake);

    // For simplicity don't exclude transitional low difficulty blocks.
    uint32_t epochDuration = height - CryptoNote::parameters::UPGRADE_HEIGHT_V5;

    // Calculate average historic difficulty for current, post-ASICs epoch
    // to eliminate their innfluence.
    uint64_t epochAvgDifficulty = m_handler.getAvgDifficulty(CryptoNote::parameters::UPGRADE_HEIGHT_V5, CryptoNote::parameters::UPGRADE_HEIGHT_V5) - m_handler.getAvgDifficulty(height, height - epochDuration);
    epochAvgDifficulty = epochAvgDifficulty == 0 ? nextDifficulty : epochAvgDifficulty;

    logger(INFO) << "Avg.  Diff: " << epochAvgDifficulty << " for window: " << epochDuration;

    // calculate difficulty-adjusted stake
    uint64_t adjustedStake = static_cast<uint64_t>(static_cast<double>(baseStake) * static_cast<double>(nextDifficulty) / static_cast<double>(epochAvgDifficulty));

    logger(INFO) << "Adj. Stake: " << m_currency.formatAmount(adjustedStake);

    // Having stake now request stake deposit transaction
    Tools::wallet_rpc::COMMAND_RPC_CONSTRUCT_STAKE_TX::request req;
    Tools::wallet_rpc::COMMAND_RPC_CONSTRUCT_STAKE_TX::response res;

    req.address = m_currency.accountAddressAsString(m_mine_address);
    req.stake = std::min<uint64_t>(adjustedStake, CryptoNote::parameters::STAKE_MAX_LIMIT);
    req.mixin = m_mixin;
    req.unlock_time = m_currency.isTestnet() ? height + CryptoNote::parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW : height + CryptoNote::parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V1;
    req.reward = reward;
    req.extra_nonce = Common::toHex(extra_nonce);

    try {
      if (local_dispatcher) {
        System::Dispatcher localDispatcher;
        HttpClient httpClient(localDispatcher, m_wallet_host, m_wallet_port);
        invokeJsonRpcCommand(httpClient, "construct_stake_tx", req, res);
      }
      else {
        HttpClient httpClient(m_dispatcher, m_wallet_host, m_wallet_port);
        invokeJsonRpcCommand(httpClient, "construct_stake_tx", req, res);
      }

      // if wallet balance is insufficient stop miner
      if (res.balance < req.stake) {
        logger(ERROR) << "Insufficient wallet balance: "
          << m_currency.formatAmount(res.balance)
          << ", of required "
          << m_currency.formatAmount(req.stake);

        return false;
      }

      // convenience log balance and stake
      logger(INFO) << "Wallet balance: " << m_currency.formatAmount(res.balance);
      logger(INFO) << "Current stake: " << m_currency.formatAmount(req.stake);
      //merge_hr();

      BinaryArray tx_blob;
      if (!Common::fromHex(res.tx_as_hex, tx_blob))
      {
        logger(ERROR) << "Failed to parse tx from hexbuff";
        return false;
      }
      Crypto::Hash tx_hash = NULL_HASH;
      Crypto::Hash tx_prefixt_hash = NULL_HASH;
      if (!parseAndValidateTransactionFromBinaryArray(tx_blob, transaction, tx_hash, tx_prefixt_hash)) {
        logger(ERROR) << "Could not parse tx from blob";
        return false;
      }
    }
    catch (const ConnectException& e) {
      logger(ERROR) << "Failed to connect to wallet: " << e.what();
      return false;
    }
    catch (const std::runtime_error& e) {
      logger(ERROR) << "Runtime error in requestStakeTransaction(): " << e.what();
      return false;
    }
    catch (const std::exception& e) {
      logger(ERROR) << "Exception in requestStakeTransaction(): " << e.what();
      return false;
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::request_block_template(bool wait_wallet_refresh, bool local_dispatcher) {
    if (wait_wallet_refresh) {
      logger(INFO) << "Give wallet few seconds to refresh...";
      std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    }

    Block bl = boost::value_initialized<Block>();
    difficulty_type di = 0;
    uint32_t height;
    CryptoNote::BinaryArray extra_nonce;

    if(m_extra_messages.size() && m_config.current_extra_message_index < m_extra_messages.size()) {
      extra_nonce = m_extra_messages[m_config.current_extra_message_index];
    }

    // 1) First, create block template with coinbase tx
    uint64_t fee;
    if (!m_handler.get_block_template(bl, fee, m_mine_address, di, height, extra_nonce)) {
      logger(ERROR) << "Failed to get_block_template(), stopping mining";
      return false;
    }

    // 2) Get stake tx from wallet RPC
    // for blocks prior v5 skip these steps
    if (bl.majorVersion >= CryptoNote::BLOCK_MAJOR_VERSION_5) {
      Transaction empty_tx = boost::value_initialized<Transaction>();
      Transaction stake_tx = empty_tx;

      // get block reward from coinbase tx and pass it to wallet
      uint64_t blockReward = 0;
      for (const auto& o : bl.baseTransaction.outputs) {
        blockReward += o.amount;
      }

      // request stake tx from wallet
      if (!requestStakeTransaction(blockReward, fee, height, extra_nonce, wait_wallet_refresh, local_dispatcher, stake_tx)) {
        logger(DEBUGGING) << "Failed to request stake transaction from wallet";
        return false;
      }

      // check that we actually got stake tx
      if (getObjectHash(stake_tx) == getObjectHash(empty_tx)) {
        logger(ERROR) << "Failed to get stake transaction, it's empty";
        return false;
      }

      // 3) Replace coibase tx with stake tx in block template
      bl.baseTransaction = stake_tx;
    }

    // 4) Set block template
    set_block_template(bl, di);
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_idle()
  {
    m_update_block_template_interval.call([&](){
      if (is_mining())
        request_block_template(false, false);
      return true;
    });

    m_update_merge_hr_interval.call([&](){
      merge_hr();
      return true;
    });

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::do_print_hashrate(bool do_hr)
  {
    m_do_print_hashrate = do_hr;
  }

  uint64_t millisecondsSinceEpoch() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
  }

  //-----------------------------------------------------------------------------------------------------
  void miner::merge_hr()
  {
    if(m_last_hr_merge_time && is_mining()) {
      m_current_hash_rate = m_hashes * 1000 / (millisecondsSinceEpoch() - m_last_hr_merge_time + 1);
      std::lock_guard<std::mutex> lk(m_last_hash_rates_lock);
      m_last_hash_rates.push_back(m_current_hash_rate);
      if(m_last_hash_rates.size() > 19)
        m_last_hash_rates.pop_front();

      if(m_do_print_hashrate) {
        uint64_t total_hr = std::accumulate(m_last_hash_rates.begin(), m_last_hash_rates.end(), static_cast<uint64_t>(0));
        float hr = static_cast<float>(total_hr)/static_cast<float>(m_last_hash_rates.size())/static_cast<float>(1000);
        logger(INFO) << "Hashrate: " << std::setprecision(2) << std::fixed << hr << " kH/s";
      }
    }
    
    m_last_hr_merge_time = millisecondsSinceEpoch();
    m_hashes = 0;
  }

  bool miner::init(const MinerConfig& config) {
    if (!config.extraMessages.empty()) {
      std::string buff;
      if (!Common::loadFileToString(config.extraMessages, buff)) {
        logger(ERROR, BRIGHT_RED) << "Failed to load file with extra messages: " << config.extraMessages; 
        return false; 
      }
      std::vector<std::string> extra_vec;
      boost::split(extra_vec, buff, boost::is_any_of("\n"), boost::token_compress_on );
      m_extra_messages.resize(extra_vec.size());
      for(size_t i = 0; i != extra_vec.size(); i++) {
        boost::algorithm::trim(extra_vec[i]);
        if(!extra_vec[i].size())
          continue;
        BinaryArray ba = Common::asBinaryArray(Common::base64Decode(extra_vec[i]));
        if(buff != "0")
          m_extra_messages[i] = ba;
      }
      m_config_folder_path = boost::filesystem::path(config.extraMessages).parent_path().string();
      m_config = boost::value_initialized<decltype(m_config)>();

      std::string filebuf;
      if (Common::loadFileToString(m_config_folder_path + "/" + CryptoNote::parameters::MINER_CONFIG_FILE_NAME, filebuf)) {
        loadFromJson(m_config, filebuf);
      }

      logger(INFO) << "Loaded " << m_extra_messages.size() << " extra messages, current index " << m_config.current_extra_message_index;
    }

    if (!config.walletHost.empty()) {
      m_wallet_host = config.walletHost;
    }

    if (config.walletPort != 0) {
      m_wallet_port = config.walletPort;
    }

    if (config.stakeMixin != 0) {
      m_mixin = config.stakeMixin;
    }

    if(!config.startMining.empty()) {
      if (!m_currency.parseAccountAddressString(config.startMining, m_mine_address)) {
        logger(ERROR) << "Target account address " << config.startMining << " has wrong format, starting daemon canceled";
        return false;
      }
      m_threads_total = 1;
      m_do_mining = true;
      if(config.miningThreads > 0) {
        m_threads_total = config.miningThreads;
      }
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::is_mining()
  {
    return !m_stop;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::start(const AccountPublicAddress& adr, size_t threads_count, std::string wallet_host, uint16_t wallet_port, size_t mixin)
  {   
    if (is_mining()) {
      logger(ERROR) << "Starting miner but it's already started";
      return false;
    }

    std::lock_guard<std::mutex> lk(m_threads_lock);

    if(!m_threads.empty()) {
      logger(ERROR) << "Unable to start miner because there are active mining threads";
      return false;
    }

    m_mine_address = adr;
    m_threads_total = static_cast<uint32_t>(threads_count);
    m_starter_nonce = Crypto::rand<uint32_t>();

    m_wallet_host = wallet_host;
    m_wallet_port = wallet_port;
	  m_mixin = mixin;

    // always request block template on start
    if (!request_block_template(false, true)) {
      logger(ERROR) << "Unable to start miner because block template request was unsuccessful";
      return false;
    }

    m_stop = false;
    m_pausers_count = 0; // in case mining wasn't resumed after pause

    for (uint32_t i = 0; i != threads_count; i++) {
      m_threads.push_back(std::thread(std::bind(&miner::worker_thread, this, i)));
    }

    logger(INFO) << "Mining has started with " << threads_count << " threads, good luck!";
    return true;
  }
  
  //-----------------------------------------------------------------------------------------------------
  uint64_t miner::get_speed()
  {
    if(is_mining())
      return m_current_hash_rate;
    else
      return 0;
  }
  
  //-----------------------------------------------------------------------------------------------------
  void miner::send_stop_signal() 
  {
    m_stop = true;
  }

  //-----------------------------------------------------------------------------------------------------
  bool miner::stop()
  {
    send_stop_signal();

    std::lock_guard<std::mutex> lk(m_threads_lock);

    for (auto& th : m_threads) {
      th.detach();
    }

    m_threads.clear();
    logger(INFO) << "Mining has been stopped, " << m_threads.size() << " finished" ;
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::find_nonce_for_given_block(Crypto::cn_context &context, Block& bl, const difficulty_type& diffic) {

    unsigned nthreads = std::thread::hardware_concurrency();

    if (nthreads > 0 && diffic > 5) {
      std::vector<std::future<void>> threads(nthreads);
      std::atomic<uint32_t> foundNonce;
      std::atomic<bool> found(false);
      uint32_t startNonce = Crypto::rand<uint32_t>();

      for (unsigned i = 0; i < nthreads; ++i) {
        threads[i] = std::async(std::launch::async, [&, i]() {
          Crypto::cn_context localctx;
          Crypto::Hash h;

          Block lb(bl); // copy to local block

          for (uint32_t nonce = startNonce + i; !found; nonce += nthreads) {
            lb.nonce = nonce;

            if (!get_block_longhash(localctx, lb, h)) {
              return;
            }

            if (check_hash(h, diffic)) {
              foundNonce = nonce;
              found = true;
              return;
            }
          }
        });
      }

      for (auto& t : threads) {
        t.wait();
      }

      if (found) {
        bl.nonce = foundNonce.load();
      }

      return found;
    } else {
      for (; bl.nonce != std::numeric_limits<uint32_t>::max(); bl.nonce++) {
        Crypto::Hash h;
        if (!get_block_longhash(context, bl, h)) {
          return false;
        }

        if (check_hash(h, diffic)) {
          return true;
        }
      }
    }

    return false;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::on_synchronized()
  {
    if(m_do_mining) {
      start(m_mine_address, m_threads_total, m_wallet_host, m_wallet_port, m_mixin);
    }
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::pause()
  {
    std::lock_guard<std::mutex> lk(m_miners_count_lock);
    ++m_pausers_count;
    if(m_pausers_count == 1 && is_mining())
      logger(TRACE) << "MINING PAUSED";
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::resume()
  {
    std::lock_guard<std::mutex> lk(m_miners_count_lock);
    --m_pausers_count;
    if(m_pausers_count < 0)
    {
      m_pausers_count = 0;
      logger(ERROR) << "Unexpected miner::resume() called";
    }
    if(!m_pausers_count && is_mining())
      logger(TRACE) << "MINING RESUMED";
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::worker_thread(uint32_t th_local_index)
  {
    logger(INFO) << "Miner thread was started ["<< th_local_index << "]";
    uint32_t nonce = m_starter_nonce + th_local_index;
    difficulty_type local_diff = 0;
    uint32_t local_template_ver = 0;
    Crypto::cn_context context;
    Block b;

    while(!m_stop)
    {
      if(m_pausers_count) //anti split workaround
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        continue;
      }

      if(local_template_ver != m_template_no) {
        std::unique_lock<std::mutex> lk(m_template_lock);
        b = m_template;
        local_diff = m_diffic;
        lk.unlock();

        local_template_ver = m_template_no;
        nonce = m_starter_nonce + th_local_index;
      }

      if(!local_template_ver)//no any set_block_template call
      {
        logger(TRACE) << "Block template not set yet";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        continue;
      }

      b.nonce = nonce;
      Crypto::Hash h;
      if (!m_stop && !get_block_longhash(context, b, h)) {
        logger(ERROR) << "Failed to get block long hash";
        m_stop = true;
      }

      if (!m_stop && check_hash(h, local_diff))
      {
        //we lucky!
        ++m_config.current_extra_message_index;

        logger(INFO, GREEN) << "Found block for difficulty: " 
                            << local_diff << std::endl 
                            << " pow: " << Common::podToHex(h);

        Crypto::Hash id;
        if (get_block_hash(b, id))
          logger(INFO, GREEN) << "hash: " << Common::podToHex(id);

        if(!m_handler.handle_block_found(b)) {
          --m_config.current_extra_message_index;
        } else {
          //success update, lets update config
          Common::saveStringToFile(m_config_folder_path + "/" + CryptoNote::parameters::MINER_CONFIG_FILE_NAME, storeToJson(m_config));
        }
      }

      nonce += m_threads_total;
      ++m_hashes;
    }
    logger(INFO) << "Miner thread stopped ["<< th_local_index << "]";
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
}

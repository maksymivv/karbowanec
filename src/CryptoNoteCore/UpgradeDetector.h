// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#include <algorithm>
#include <cstdint>
#include <ctime>

#include "Common/StringTools.h"
#include "Common/Varint.hpp"
#include "CryptoNoteCore/Difficulty.h"
#include "CryptoNoteCore/CryptoNoteBasicImpl.h"
#include "CryptoNoteCore/CryptoNoteFormatUtils.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Currency.h"
#include "CryptoNoteCore/DB.hpp"
#include "CryptoNoteConfig.h"
#include <CryptoTypes.h>
#include <CryptoNote.h>
#include <Logging/LoggerRef.h>
#include "Serialization/ISerializer.h"
#include "Serialization/SerializationTools.h"

#undef ERROR

namespace CryptoNote {
  class UpgradeDetectorBase {
  public:
    enum : uint32_t {
      UNDEF_HEIGHT = static_cast<uint32_t>(-1),
    };
  };

  static_assert(CryptoNote::UpgradeDetectorBase::UNDEF_HEIGHT == UINT32_C(0xFFFFFFFF), "UpgradeDetectorBase::UNDEF_HEIGHT has invalid value");

  template<typename DB>
  class BasicUpgradeDetector : public UpgradeDetectorBase {
  public:
    typedef Platform::DB DB;

    BasicUpgradeDetector(const Currency& currency, DB& bdb, uint8_t targetVersion, const std::string& config_folder, Logging::ILogger& log) :
      m_currency(currency),
      m_targetVersion(targetVersion),
      m_votingCompleteHeight(UNDEF_HEIGHT),
      logger(log, "upgrade"),
      m_db(bdb) { }

    bool init() {
      uint32_t upgradeHeight = m_currency.upgradeHeight(m_targetVersion);
      
      Crypto::Hash tail_id;
      DB::Cursor cur = m_db.rbegin(BLOCK_INDEX_PREFIX);
      m_height = cur.end() ? 0 : Common::integer_cast<uint32_t>(Common::read_varint_sqlite4(cur.get_suffix())) + 1; // incl. block zero
      BinaryArray ba = cur.get_value_array();
      memcpy(&tail_id, ba.data(), ba.size());
      auto key = BLOCK_PREFIX + DB::to_binary_key(tail_id.data, sizeof(tail_id.data)) + BLOCK_SUFFIX;
      if (!m_db.get(key, ba))
        logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: init() can't get block from DB: " << Common::podToHex(tail_id);
      fromBinaryArray(m_tip_b, ba);

      if (upgradeHeight == UNDEF_HEIGHT) {
        if (cur.end()) {
          m_votingCompleteHeight = UNDEF_HEIGHT;

        } else if (m_targetVersion - 1 == m_tip_b.bl.majorVersion) {
          m_votingCompleteHeight = findVotingCompleteHeight(static_cast<uint32_t>(m_height - 1));

        } else if (m_targetVersion <= m_tip_b.bl.majorVersion) {
          uint8_t v;
          BinaryArray ba;
          BlockEntry be = m_tip_b;
          do {
            auto key = BLOCK_PREFIX + DB::to_binary_key(be.bl.previousBlockHash.data, sizeof(be.bl.previousBlockHash.data)) + BLOCK_SUFFIX;
            if (!m_db.get(key, ba))
              return false;
            if (!fromBinaryArray(be, ba))
              return false;
            v = be.bl.majorVersion;
          } while (v < m_targetVersion);

          uint32_t upgradeHeight = be.height;

          m_votingCompleteHeight = findVotingCompleteHeight(upgradeHeight);
          if (m_votingCompleteHeight == UNDEF_HEIGHT) {
            logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: voting complete height isn't found, upgrade height = " << upgradeHeight;
            return false;
          }
        } else {
          m_votingCompleteHeight = UNDEF_HEIGHT;
        }
      } else if (!cur.end()) {
        if (m_height <= upgradeHeight + 1) {
          if (m_tip_b.bl.majorVersion >= m_targetVersion) {
            logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: block at height " << (m_height - 1) <<
              " has invalid version " << static_cast<int>(m_tip_b.bl.majorVersion) <<
              ", expected " << static_cast<int>(m_targetVersion - 1) << " or less";
            return false;
          }
        } else {
          std::string sb;
          BinaryArray bab;
          BlockEntry beb;
          if(!m_db.get(BLOCK_INDEX_PREFIX + Common::write_varint_sqlite4(upgradeHeight), sb))
            return false;
          if (!m_db.get(BLOCK_PREFIX + sb + BLOCK_SUFFIX, bab))
            return false;
          if (!fromBinaryArray(beb, bab))
            return false;
          int blockVersionAtUpgradeHeight = beb.bl.majorVersion;
          if (blockVersionAtUpgradeHeight != m_targetVersion - 1) {
            logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: block at height " << upgradeHeight <<
              " (before upgrade) has invalid version " << blockVersionAtUpgradeHeight <<
              ", expected " << static_cast<int>(m_targetVersion - 1);
            return false;
          }

          std::string sa;
          BinaryArray baa;
          BlockEntry bea;
          if (!m_db.get(BLOCK_INDEX_PREFIX + Common::write_varint_sqlite4((upgradeHeight + 1)), sa))
            return false;
          if (!m_db.get(BLOCK_PREFIX + sa + BLOCK_SUFFIX, baa))
            return false;
          if (!fromBinaryArray(bea, baa))
            return false;

          int blockVersionAfterUpgradeHeight = bea.bl.majorVersion;
          if (blockVersionAfterUpgradeHeight != m_targetVersion) {
            logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: block at height " << (upgradeHeight + 1) <<
              " (after upgrade) has invalid version " << blockVersionAfterUpgradeHeight <<
              ", expected " << static_cast<int>(m_targetVersion);
            return false;
          }
        }
      }

      return true;
    }

    uint8_t targetVersion() const { return m_targetVersion; }
    uint32_t votingCompleteHeight() const { return m_votingCompleteHeight; }

    uint32_t upgradeHeight() const {
      if (m_currency.upgradeHeight(m_targetVersion) == UNDEF_HEIGHT) {
        return m_votingCompleteHeight == UNDEF_HEIGHT ? UNDEF_HEIGHT : m_currency.calculateUpgradeHeight(m_votingCompleteHeight);
      } else {
        return m_currency.upgradeHeight(m_targetVersion);
      }
    }

    void blockPushed() {
      Crypto::Hash tail_id;
      DB::Cursor cur = m_db.rbegin(BLOCK_INDEX_PREFIX);
      m_height = cur.end() ? 0 : Common::integer_cast<uint32_t>(Common::read_varint_sqlite4(cur.get_suffix())) + 1; // incl. block zero
      BinaryArray ba = cur.get_value_array();
      memcpy(&tail_id, ba.data(), ba.size());
      auto key = BLOCK_PREFIX + DB::to_binary_key(tail_id.data, sizeof(tail_id.data)) + BLOCK_SUFFIX;
      if (!m_db.get(key, ba))
        logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: blockPushed() can't get block from DB: " << Common::podToHex(tail_id);
      fromBinaryArray(m_tip_b, ba);

      if (m_currency.upgradeHeight(m_targetVersion) != UNDEF_HEIGHT) {
        if (m_height <= m_currency.upgradeHeight(m_targetVersion) + 1) {
          assert(m_tip_b.bl.majorVersion <= m_targetVersion - 1);
        } else {
          assert(m_tip_b.bl.majorVersion >= m_targetVersion);
        }

      } else if (m_votingCompleteHeight != UNDEF_HEIGHT) {
        assert(m_height > m_votingCompleteHeight);

        if (m_height <= upgradeHeight()) {
          assert(m_tip_b.bl.majorVersion == m_targetVersion - 1);

          if (m_height % (60 * 60 / m_currency.difficultyTarget()) == 0) {
            auto interval = m_currency.difficultyTarget() * (upgradeHeight() - m_height + 2);
            time_t upgradeTimestamp = time(nullptr) + static_cast<time_t>(interval);
            struct tm* upgradeTime = localtime(&upgradeTimestamp);;
            char upgradeTimeStr[40];
            strftime(upgradeTimeStr, 40, "%H:%M:%S %Y.%m.%d", upgradeTime);

            logger(Logging::INFO, Logging::BRIGHT_GREEN) << "###### UPGRADE is going to happen after block index " << upgradeHeight() << " at about " <<
              upgradeTimeStr << " (in " << Common::timeIntervalToString(interval) << ")! Current last block index " << (m_height - 1) <<
              ", hash " << get_block_hash(m_tip_b.bl);
          }
        } else if (m_height == upgradeHeight() + 1) {
          //assert(m_blockchain.back().bl.majorVersion == m_targetVersion - 1);
          assert(m_tip_b.bl.majorVersion == m_targetVersion - 1);

          logger(Logging::INFO, Logging::BRIGHT_GREEN) << "###### UPGRADE has happened! Starting from block index " << (upgradeHeight() + 1) <<
            " blocks with major version below " << static_cast<int>(m_targetVersion) << " will be rejected!";
        } else {
          //assert(m_blockchain.back().bl.majorVersion == m_targetVersion);
          assert(m_tip_b.bl.majorVersion == m_targetVersion);
        }

      } else {
        uint32_t lastBlockHeight = m_height - 1;
        if (isVotingComplete(lastBlockHeight)) {
          m_votingCompleteHeight = lastBlockHeight;
          logger(Logging::INFO, Logging::BRIGHT_GREEN) << "###### UPGRADE voting complete at block index " << m_votingCompleteHeight <<
            "! UPGRADE is going to happen after block index " << upgradeHeight() << "!";
        }
      }
    }

    void blockPopped() {
      if (m_votingCompleteHeight != UNDEF_HEIGHT) {
        assert(m_currency.upgradeHeight(m_targetVersion) == UNDEF_HEIGHT);

        
        Crypto::Hash tail_id;
        DB::Cursor cur = m_db.rbegin(BLOCK_INDEX_PREFIX);
        m_height = cur.end() ? 0 : Common::integer_cast<uint32_t>(Common::read_varint_sqlite4(cur.get_suffix())) + 1; // incl. block zero
        assert(m_height > 0);
        BinaryArray ba = cur.get_value_array();
        memcpy(&tail_id, ba.data(), ba.size());
        auto key = BLOCK_PREFIX + DB::to_binary_key(tail_id.data, sizeof(tail_id.data)) + BLOCK_SUFFIX;
        if (!m_db.get(key, ba))
          logger(Logging::ERROR, Logging::BRIGHT_RED) << "Internal error: blockPopped() can't get block from DB: " << Common::podToHex(tail_id);
        fromBinaryArray(m_tip_b, ba);

        if (m_height == m_votingCompleteHeight) {
          logger(Logging::INFO, Logging::BRIGHT_YELLOW) << "###### UPGRADE after block index " << upgradeHeight() << " has been canceled!";
          m_votingCompleteHeight = UNDEF_HEIGHT;
        } else {
          assert(m_height > m_votingCompleteHeight);
        }
      }
    }

    size_t getNumberOfVotes(uint32_t height) {
      if (height < m_currency.upgradeVotingWindow() - 1) {
        return 0;
      }

      size_t voteCounter = 0;
      for (size_t i = height + 1 - m_currency.upgradeVotingWindow(); i <= height; ++i) {
        const auto& b = m_tip_b.bl;
        voteCounter += (b.majorVersion == m_targetVersion - 1) && (b.minorVersion == BLOCK_MINOR_VERSION_1) ? 1 : 0;
      }

      return voteCounter;
    }

  protected:
    DB m_db;

  private:
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


    uint32_t findVotingCompleteHeight(uint32_t probableUpgradeHeight) {
      assert(m_currency.upgradeHeight(m_targetVersion) == UNDEF_HEIGHT);

      uint32_t probableVotingCompleteHeight = probableUpgradeHeight > m_currency.maxUpgradeDistance() ? probableUpgradeHeight - m_currency.maxUpgradeDistance() : 0;
      for (uint32_t i = probableVotingCompleteHeight; i <= probableUpgradeHeight; ++i) {
        if (isVotingComplete(i)) {
          return i;
        }
      }

      return UNDEF_HEIGHT;
    }

    bool isVotingComplete(uint32_t height) {
      assert(m_currency.upgradeHeight(m_targetVersion) == UNDEF_HEIGHT);
      assert(m_currency.upgradeVotingWindow() > 1);
      assert(m_currency.upgradeVotingThreshold() > 0 && m_currency.upgradeVotingThreshold() <= 100);

      size_t voteCounter = getNumberOfVotes(height);
      return m_currency.upgradeVotingThreshold() * m_currency.upgradeVotingWindow() <= 100 * voteCounter;
    }

  private:
    Logging::LoggerRef logger;
    const Currency& m_currency;
    uint8_t m_targetVersion;
    uint32_t m_votingCompleteHeight;
    uint32_t m_height; // blockchain height incl. zero block
    BlockEntry m_tip_b;
  };
}

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

#include "CryptoNoteCore/CryptoNoteBasic.h"
#include "CryptoNoteCore/Difficulty.h"

namespace CryptoNote {
  struct IMinerHandler {
    virtual bool handle_block_found(Block& b) = 0;
    virtual bool get_block_template(Block& b, uint64_t& fee, const AccountPublicAddress& adr, difficulty_type& diffic, uint32_t& height, const BinaryArray& ex_nonce, bool local_dispatcher, uint64_t wantedStake) = 0;
    virtual bool prepareBlockTemplate(Block& b, uint64_t& fee, const AccountPublicAddress& adr, difficulty_type& diffic, uint32_t& height, const BinaryArray& ex_nonce, size_t& median_size, size_t& txs_size, uint64_t& already_generated_coins) = 0;
    virtual bool requestStakeTransaction(uint64_t& baseStake, uint64_t& wantedStake, uint64_t& blockReward, uint32_t& height, const AccountPublicAddress& minerAddress, const CryptoNote::BinaryArray& extra_nonce, bool local_dispatcher, Transaction& transaction) = 0;
    virtual bool getBlockCumulativeDifficulty(uint32_t height, difficulty_type& difficulty) = 0;
    virtual uint64_t getNextBlockDifficulty() = 0;
    virtual uint64_t getTotalGeneratedAmount() = 0;
    virtual uint64_t getAvgDifficulty(uint32_t height, size_t window) = 0;
    virtual uint8_t getBlockMajorVersionForHeight(uint32_t height) = 0;

  protected:
    ~IMinerHandler(){};
  };
}

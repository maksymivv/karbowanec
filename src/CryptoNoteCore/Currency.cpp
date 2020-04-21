// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2017, XDN-project developers
// Copyright (c) 2016-2018, zawy12
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

#include "Currency.h"
#include <cctype>
#include <boost/algorithm/string/trim.hpp>
#include <boost/math/special_functions/round.hpp>
#include <boost/lexical_cast.hpp>
#include "../Common/Base58.h"
#include "../Common/int-util.h"
#include "../Common/FormatTools.h"
#include "../Common/StringTools.h"
#include "Account.h"
#include "CryptoNoteBasicImpl.h"
#include "CryptoNoteFormatUtils.h"
#include "CryptoNoteTools.h"
#include "TransactionExtra.h"
#include "UpgradeDetector.h"

#undef ERROR

using namespace Logging;
using namespace Common;

namespace CryptoNote {

	const std::vector<uint64_t> Currency::PRETTY_AMOUNTS = {
		1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 20, 30, 40, 50, 60, 70, 80, 90,
		100, 200, 300, 400, 500, 600, 700, 800, 900,
		1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000,
		10000, 20000, 30000, 40000, 50000, 60000, 70000, 80000, 90000,
		100000, 200000, 300000, 400000, 500000, 600000, 700000, 800000, 900000,
		1000000, 2000000, 3000000, 4000000, 5000000, 6000000, 7000000, 8000000, 9000000,
		10000000, 20000000, 30000000, 40000000, 50000000, 60000000, 70000000, 80000000, 90000000,
		100000000, 200000000, 300000000, 400000000, 500000000, 600000000, 700000000, 800000000, 900000000,
		1000000000, 2000000000, 3000000000, 4000000000, 5000000000, 6000000000, 7000000000, 8000000000, 9000000000,
		10000000000, 20000000000, 30000000000, 40000000000, 50000000000, 60000000000, 70000000000, 80000000000, 90000000000,
		100000000000, 200000000000, 300000000000, 400000000000, 500000000000, 600000000000, 700000000000, 800000000000, 900000000000,
		1000000000000, 2000000000000, 3000000000000, 4000000000000, 5000000000000, 6000000000000, 7000000000000, 8000000000000, 9000000000000,
		10000000000000, 20000000000000, 30000000000000, 40000000000000, 50000000000000, 60000000000000, 70000000000000, 80000000000000, 90000000000000,
		100000000000000, 200000000000000, 300000000000000, 400000000000000, 500000000000000, 600000000000000, 700000000000000, 800000000000000, 900000000000000,
		1000000000000000, 2000000000000000, 3000000000000000, 4000000000000000, 5000000000000000, 6000000000000000, 7000000000000000, 8000000000000000, 9000000000000000,
		10000000000000000, 20000000000000000, 30000000000000000, 40000000000000000, 50000000000000000, 60000000000000000, 70000000000000000, 80000000000000000, 90000000000000000,
		100000000000000000, 200000000000000000, 300000000000000000, 400000000000000000, 500000000000000000, 600000000000000000, 700000000000000000, 800000000000000000, 900000000000000000,
		1000000000000000000, 2000000000000000000, 3000000000000000000, 4000000000000000000, 5000000000000000000, 6000000000000000000, 7000000000000000000, 8000000000000000000, 9000000000000000000,
		10000000000000000000ull
	};

	bool Currency::init() {
		if (!generateGenesisBlock()) {
			logger(ERROR, BRIGHT_RED) << "Failed to generate genesis block";
			return false;
		}

		if (!get_block_hash(m_genesisBlock, m_genesisBlockHash)) {
			logger(ERROR, BRIGHT_RED) << "Failed to get genesis block hash";
			return false;
		}

		if (isTestnet()) {
			m_upgradeHeightV2 = 10;
			m_upgradeHeightV3 = 60;
			m_upgradeHeightV4 = 70;
			m_upgradeHeightV5 = 80;
			m_blocksFileName = "testnet_" + m_blocksFileName;
			m_blocksCacheFileName = "testnet_" + m_blocksCacheFileName;
			m_blockIndexesFileName = "testnet_" + m_blockIndexesFileName;
			m_txPoolFileName = "testnet_" + m_txPoolFileName;
			m_blockchainIndicesFileName = "testnet_" + m_blockchainIndicesFileName;
		}

		return true;
	}

	bool Currency::generateGenesisBlock() {
		m_genesisBlock = boost::value_initialized<Block>();

		// Hard code coinbase tx in genesis block, because "tru" generating tx use random, but genesis should be always the same
		std::string genesisCoinbaseTxHex = GENESIS_COINBASE_TX_HEX;
		BinaryArray minerTxBlob;

		bool r =
			fromHex(genesisCoinbaseTxHex, minerTxBlob) &&
			fromBinaryArray(m_genesisBlock.baseTransaction, minerTxBlob);

		if (!r) {
			logger(ERROR, BRIGHT_RED) << "failed to parse coinbase tx from hard coded blob";
			return false;
		}

		m_genesisBlock.majorVersion = BLOCK_MAJOR_VERSION_1;
		m_genesisBlock.minorVersion = BLOCK_MINOR_VERSION_0;
		m_genesisBlock.timestamp = GENESIS_TIMESTAMP;
		m_genesisBlock.nonce = GENESIS_NONCE;
		if (m_testnet) {
			++m_genesisBlock.nonce;
		}
		//miner::find_nonce_for_given_block(bl, 1, 0);

		return true;
	}

	size_t Currency::blockGrantedFullRewardZoneByBlockVersion(uint8_t blockMajorVersion) const {
		if (blockMajorVersion >= BLOCK_MAJOR_VERSION_3) {
      return CryptoNote::parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2;
		}
		else {
			return m_blockGrantedFullRewardZone;
		}
	}

	uint32_t Currency::upgradeHeight(uint8_t majorVersion) const {
		if (majorVersion == BLOCK_MAJOR_VERSION_5) {
			return m_upgradeHeightV5;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_4) {
			return m_upgradeHeightV4;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_2) {
			return m_upgradeHeightV2;
		}
		else if (majorVersion == BLOCK_MAJOR_VERSION_3) {
			return m_upgradeHeightV3;
		}
		else {
			return static_cast<uint32_t>(-1);
		}
	}

  uint64_t Currency::calculateReward(uint8_t blockMajorVersion, uint32_t height, uint64_t alreadyGeneratedCoins) const {
    // Initial emission
    // the 1000000 coins in first 1000 blocks
    // only fees later
    // zero in genesis
    return height == 0 ? 0 : (blockMajorVersion == 1 ? CryptoNote::parameters::START_BLOCK_REWARD : 0/*here can define other variants*/);
  }

  bool Currency::getBlockReward(uint8_t blockMajorVersion, uint32_t height, size_t medianSize, size_t currentBlockSize, uint64_t alreadyGeneratedCoins,
    uint64_t fee, uint64_t& reward, int64_t& emissionChange) const {

    uint64_t baseReward = calculateReward(blockMajorVersion, height, alreadyGeneratedCoins);

    size_t blockGrantedFullRewardZone = blockGrantedFullRewardZoneByBlockVersion(blockMajorVersion);
    medianSize = std::max(medianSize, blockGrantedFullRewardZone);
    if (currentBlockSize > UINT64_C(2) * medianSize) {
      logger(DEBUGGING) << "Block cumulative size is too big: " << currentBlockSize << ", expected less than " << 2 * medianSize;
      return false;
    }

    uint64_t penalizedBaseReward = getPenalizedAmount(baseReward, medianSize, currentBlockSize);
    uint64_t penalizedFee = blockMajorVersion >= BLOCK_MAJOR_VERSION_2 ? getPenalizedAmount(fee, medianSize, currentBlockSize) : fee;
    if (cryptonoteCoinVersion() == 1) {
      penalizedFee = getPenalizedAmount(fee, medianSize, currentBlockSize);
    }

    emissionChange = penalizedBaseReward - (fee - penalizedFee);
    reward = penalizedBaseReward + penalizedFee;

    return true;
  }

  uint64_t Currency::calculateInterest(uint64_t amount, uint32_t term) const {
    assert(m_depositMinTerm <= term && term <= m_depositMaxTerm);
    assert(static_cast<uint64_t>(term)* m_depositMaxTotalRate > m_depositMinTotalRateFactor);

    uint64_t a = static_cast<uint64_t>(term) * m_depositMaxTotalRate - m_depositMinTotalRateFactor;
    uint64_t bHi;
    uint64_t bLo = mul128(amount, a, &bHi);

    uint64_t interestHi;
    uint64_t interestLo;
    assert(std::numeric_limits<uint32_t>::max() / 100 > m_depositMaxTerm);
    div128_32(bHi, bLo, static_cast<uint32_t>(100 * m_depositMaxTerm), &interestHi, &interestLo);
    assert(interestHi == 0);

    return interestLo;
  }

  std::vector<std::pair<uint32_t, uint64_t>> Currency::disburseInterest(uint64_t amount, uint32_t term) const {
    assert(m_depositMinAmount <= amount);
    assert(m_depositMinTerm <= term && term <= m_depositMaxTerm);
    const size_t n = CryptoNote::parameters::DEPOSIT_DISBURSEMENT_PARTS; // always disburse interest in 12 parts

    std::vector<std::pair<uint32_t, uint64_t>> chunks;
    std::vector<uint32_t> terms;
    std::vector<uint64_t> amounts;

    if (amount % n == 0) {
      for (size_t i = 0; i < n; i++) {
        amounts.push_back(amount / n);
      }
    } else {
      uint64_t zp = n - (amount % n);
      uint64_t pp = amount / n;
      for (size_t i = 0; i < n; i++) {
        if (i >= zp) {
          amounts.push_back(pp + 1);
        } else {
          amounts.push_back(pp);
        }
      }
    }
    if (term % n == 0) {
      for (size_t i = 0; i < n; i++) {
        terms.push_back(term / n);
      }
    } else {
      uint32_t zp = n - (term % n);
      uint32_t pp = term / n;
      for (size_t i = 0; i < n; i++) {
        if (i >= zp) {
          terms.push_back(pp + 1);
        } else {
          terms.push_back(pp);
        }
      }
    }
    for (size_t i = 0; i < n; i++) {
      chunks.push_back(std::make_pair(terms[i], amounts[i]));
    }

    return chunks;
  }

  // unlockTime must be the same as largest of outputUnlockTimes
  bool Currency::getDepositTerm(const Transaction& tx, uint32_t& term) const {
    std::vector<uint64_t> unlocktimes = tx.outputUnlockTimes;
    sort(unlocktimes.begin(), unlocktimes.end());
    std::reverse(unlocktimes.begin(), unlocktimes.end());
    if (unlocktimes.front() < depositMinTerm() && tx.unlockTime != unlocktimes.front()) {
      logger(ERROR) << "Invalid deposit term";
      return false;
    }

    term = (uint32_t)tx.unlockTime;
    return true;
  }

  bool Currency::getTransactionDepositInfo(const Transaction& tx, uint64_t& deposit, uint64_t& interest, uint64_t& fee, uint32_t& term) const {
    uint64_t inputsAmount = getInputAmount(tx);
    uint64_t outputsAmount = 0, calculatedInterest = 0, actualInterest = 0, change = 0;
    std::vector<std::pair<uint32_t, uint64_t>> unlockTimesAndAmounts; // term, amount
    std::vector<std::pair<uint32_t, uint64_t>> actualInterestPayouts;

    for (uint64_t i = 0; i < tx.outputs.size(); ++i) {
      TransactionOutput o = tx.outputs[i];
      outputsAmount += o.amount;
      unlockTimesAndAmounts.push_back(std::make_pair(tx.outputUnlockTimes[i], o.amount));
    }

    if (!(outputsAmount > inputsAmount)) {
      logger(DEBUGGING) << "Not a deposit";
      return false;
    }

    // deposit term is the largest unlock time
    sort(unlockTimesAndAmounts.begin(), unlockTimesAndAmounts.end());
    std::reverse(unlockTimesAndAmounts.begin(), unlockTimesAndAmounts.end());

    // unlockTime must be the same as the largest of outputUnlockTimes
    if (unlockTimesAndAmounts.front().first < depositMinTerm() || (uint32_t)tx.unlockTime != unlockTimesAndAmounts.front().first) {
      logger(DEBUGGING) << "Invalid deposit term";
      return false;
    }
    term = unlockTimesAndAmounts.front().first;

    for (uint64_t i = 0; i < unlockTimesAndAmounts.size(); ++i) {
      if (unlockTimesAndAmounts[i].first == (uint32_t)tx.unlockTime) {
        deposit += unlockTimesAndAmounts[i].second;
      }
      else if (unlockTimesAndAmounts[i].first != 0) {
        actualInterest += unlockTimesAndAmounts[i].second;
        actualInterestPayouts.push_back(unlockTimesAndAmounts[i]);
      }
      else {
        change += unlockTimesAndAmounts[i].second;
      }
    }

    if (deposit < depositMinAmount()) {
      logger(DEBUGGING) << "Insufficient deposit amount: " << formatAmount(deposit) << " whereas minimum is " << formatAmount(depositMinAmount());
      return false;
    }

    calculatedInterest = calculateInterest(deposit, term);

    // compare calculated with actual
    if (actualInterest > calculatedInterest) {
      logger(DEBUGGING) << "Invalid deposit: interest amount " << formatAmount(actualInterest) << " is bigger than expected " << formatAmount(calculatedInterest);
      return false;
    }
    else if (actualInterest < calculatedInterest) {
      logger(DEBUGGING) << "Invalid deposit: underpaid interest " << formatAmount(actualInterest) << " of expected " << formatAmount(calculatedInterest);
      return false;
    }
        
    // the fee can NOT be in outputs, it's just burned and resurrected in miner's tx
    if (inputsAmount <= deposit + change) {
      logger(DEBUGGING) << "Invalid deposit due to wrong fee";
      return false;
    }
    fee = inputsAmount - (deposit + change);

    //check gradual interest disbursement
    std::vector<std::pair<uint32_t, uint64_t>> calculatedInterestPayouts = disburseInterest(deposit, term);
    if (actualInterestPayouts != calculatedInterestPayouts) {
      logger(DEBUGGING) << "Invalid deposit interest disbursement";
      return false;
    }

    return true;
  }

  bool Currency::getTransactionFee(const Transaction& tx, uint64_t & fee) const {
    uint64_t amount_in = getInputAmount(tx);
    uint64_t amount_out = getOutputAmount(tx);
    uint64_t deposit_amount = 0, deposit_interest = 0, deposit_fee = 0;
    uint32_t deposit_term = 0;
    if (amount_out > amount_in) {
      if (!getTransactionDepositInfo(tx, deposit_amount, deposit_interest, deposit_fee, deposit_term)) {
        logger(ERROR) << "Invalid deposit...";
        return false;
      }
      fee = deposit_fee;
    } else {
      fee = amount_in - amount_out;
    }

    return true;
  }

  uint64_t Currency::getTransactionFee(const Transaction& tx) const {
    uint64_t r = 0;
    if (!getTransactionFee(tx, r)) {
      r = 0;
    }
    return r;
  }

	size_t Currency::maxBlockCumulativeSize(uint64_t height) const {
		assert(height <= std::numeric_limits<uint64_t>::max() / m_maxBlockSizeGrowthSpeedNumerator);
		size_t maxSize = static_cast<size_t>(m_maxBlockSizeInitial +
			(height * m_maxBlockSizeGrowthSpeedNumerator) / m_maxBlockSizeGrowthSpeedDenominator);
		assert(maxSize >= m_maxBlockSizeInitial);
		return maxSize;
	}

	bool Currency::constructMinerTx(uint8_t blockMajorVersion, uint32_t height, size_t medianSize, uint64_t alreadyGeneratedCoins, size_t currentBlockSize,
		uint64_t fee, const AccountPublicAddress& minerAddress, Transaction& tx, const BinaryArray& extraNonce, size_t maxOuts) const {

		tx.inputs.clear();
		tx.outputs.clear();
		tx.extra.clear();

		KeyPair txkey = generateKeyPair();
		addTransactionPublicKeyToExtra(tx.extra, txkey.publicKey);
		if (!extraNonce.empty()) {
			if (!addExtraNonceToTransactionExtra(tx.extra, extraNonce)) {
				return false;
			}
		}

		BaseInput in;
		in.blockIndex = height;

		uint64_t blockReward;
		int64_t emissionChange;
		if (!getBlockReward(blockMajorVersion, height, medianSize, currentBlockSize, alreadyGeneratedCoins, fee, blockReward, emissionChange)) {
			logger(INFO) << "Block is too big";
			return false;
		}

		std::vector<uint64_t> outAmounts;
		decompose_amount_into_digits(blockReward, UINT64_C(0),
			[&outAmounts](uint64_t a_chunk) { outAmounts.push_back(a_chunk); },
			[&outAmounts](uint64_t a_dust) { outAmounts.push_back(a_dust); });

		if (!(1 <= maxOuts)) { logger(ERROR, BRIGHT_RED) << "max_out must be non-zero"; return false; }
		while (maxOuts < outAmounts.size()) {
			outAmounts[outAmounts.size() - 2] += outAmounts.back();
			outAmounts.resize(outAmounts.size() - 1);
		}

		uint64_t summaryAmounts = 0;
		for (size_t no = 0; no < outAmounts.size(); no++) {
			Crypto::KeyDerivation derivation = boost::value_initialized<Crypto::KeyDerivation>();
			Crypto::PublicKey outEphemeralPubKey = boost::value_initialized<Crypto::PublicKey>();

			bool r = Crypto::generate_key_derivation(minerAddress.viewPublicKey, txkey.secretKey, derivation);

			if (!(r)) {
				logger(ERROR, BRIGHT_RED)
					<< "while creating outs: failed to generate_key_derivation("
					<< minerAddress.viewPublicKey << ", " << txkey.secretKey << ")";
				return false;
			}

			r = Crypto::derive_public_key(derivation, no, minerAddress.spendPublicKey, outEphemeralPubKey);

			if (!(r)) {
				logger(ERROR, BRIGHT_RED)
					<< "while creating outs: failed to derive_public_key("
					<< derivation << ", " << no << ", "
					<< minerAddress.spendPublicKey << ")";
				return false;
			}

			KeyOutput tk;
			tk.key = outEphemeralPubKey;

			TransactionOutput out;
			summaryAmounts += out.amount = outAmounts[no];
			out.target = tk;
			tx.outputs.push_back(out);
		}

		if (!(summaryAmounts == blockReward)) {
			logger(ERROR, BRIGHT_RED) << "Failed to construct miner tx, summaryAmounts = " << summaryAmounts << " not equal blockReward = " << blockReward;
			return false;
		}

		tx.version = CURRENT_TRANSACTION_VERSION;
		//lock
		tx.unlockTime = height + minedMoneyUnlockWindow();
		tx.inputs.push_back(in);
		return true;
	}

	std::string Currency::accountAddressAsString(const AccountBase& account) const {
		return getAccountAddressAsStr(m_publicAddressBase58Prefix, account.getAccountKeys().address);
	}

	std::string Currency::accountAddressAsString(const AccountPublicAddress& accountPublicAddress) const {
		return getAccountAddressAsStr(m_publicAddressBase58Prefix, accountPublicAddress);
	}

	bool Currency::parseAccountAddressString(const std::string& str, AccountPublicAddress& addr) const {
		uint64_t prefix;
		if (!CryptoNote::parseAccountAddressString(prefix, addr, str)) {
			return false;
		}

		if (prefix != m_publicAddressBase58Prefix) {
			logger(DEBUGGING) << "Wrong address prefix: " << prefix << ", expected " << m_publicAddressBase58Prefix;
			return false;
		}

		return true;
	}

	std::string Currency::formatAmount(uint64_t amount) const {
		return Common::Format::formatAmount(amount);
	}

	std::string Currency::formatAmount(int64_t amount) const {
    return Common::Format::formatAmount(amount);
	}

	bool Currency::parseAmount(const std::string& str, uint64_t& amount) const {
		return Common::Format::parseAmount(str, amount);
	}

  // All that exceeds 100 bytes is charged per byte,
  // the cost of one byte is 1/100 of minimal fee
  uint64_t Currency::getFeePerByte(const uint64_t txExtraSize, const uint64_t minFee) const {
    return txExtraSize > 100 ? minFee / 100 * (txExtraSize - 100) : 0;
  }

	uint64_t Currency::roundUpMinFee(uint64_t minimalFee, int digits) const {
		uint64_t ret(0);
		std::string minFeeString = formatAmount(minimalFee);
		double minFee = boost::lexical_cast<double>(minFeeString);
		double scale = pow(10., floor(log10(fabs(minFee))) + (1 - digits));
		double roundedFee = ceil(minFee / scale) * scale;
		std::stringstream ss;
		ss << std::fixed << std::setprecision(12) << roundedFee;
		std::string roundedFeeString = ss.str();
		parseAmount(roundedFeeString, ret);
		return ret;
	}

	difficulty_type Currency::nextDifficulty(uint32_t height, uint8_t blockMajorVersion, std::vector<uint64_t> timestamps,
		std::vector<difficulty_type> cumulativeDifficulties) const {
		if (blockMajorVersion >= BLOCK_MAJOR_VERSION_2) {
			return nextDifficultyV2(height, blockMajorVersion, timestamps, cumulativeDifficulties);
		}
		else {
			return nextDifficultyV1(timestamps, cumulativeDifficulties);
		}
	}

	difficulty_type Currency::nextDifficultyV1(std::vector<uint64_t> timestamps,
				std::vector<difficulty_type> cumulativeDifficulties) const {
		assert(m_difficultyWindow >= 2);

		if (timestamps.size() > m_difficultyWindow) {
			timestamps.resize(m_difficultyWindow);
			cumulativeDifficulties.resize(m_difficultyWindow);
		}

		size_t length = timestamps.size();
		assert(length == cumulativeDifficulties.size());
		assert(length <= m_difficultyWindow);
		if (length <= 1) {
			return 1;
		}

		sort(timestamps.begin(), timestamps.end());

		size_t cutBegin, cutEnd;
		assert(2 * m_difficultyCut <= m_difficultyWindow - 2);
		if (length <= m_difficultyWindow - 2 * m_difficultyCut) {
			cutBegin = 0;
			cutEnd = length;
		}
		else {
			cutBegin = (length - (m_difficultyWindow - 2 * m_difficultyCut) + 1) / 2;
			cutEnd = cutBegin + (m_difficultyWindow - 2 * m_difficultyCut);
		}
		assert(/*cut_begin >= 0 &&*/ cutBegin + 2 <= cutEnd && cutEnd <= length);
		uint64_t timeSpan = timestamps[cutEnd - 1] - timestamps[cutBegin];
		if (timeSpan == 0) {
			timeSpan = 1;
		}

		difficulty_type totalWork = cumulativeDifficulties[cutEnd - 1] - cumulativeDifficulties[cutBegin];
		assert(totalWork > 0);

		uint64_t low, high;
		low = mul128(totalWork, m_difficultyTarget, &high);
		if (high != 0 || low + timeSpan - 1 < low) {
			return 0;
		}

		return (low + timeSpan - 1) / timeSpan;
	}

  difficulty_type Currency::nextDifficultyV2(uint32_t height, uint8_t blockMajorVersion,
    std::vector<std::uint64_t> timestamps, std::vector<difficulty_type> cumulativeDifficulties) const {

    // LWMA-1 difficulty algorithm 
    // Copyright (c) 2017-2018 Zawy, MIT License
    // See commented link below for required config file changes. Fix FTL and MTP.
    // https://github.com/zawy12/difficulty-algorithms/issues/3

    assert(timestamps.size() == cumulativeDifficulties.size());

    const int64_t T = static_cast<int64_t>(m_difficultyTarget);
    uint64_t N = cumulativeDifficulties.size() - 1; // adjust for new epoch difficulty reset, N should be by 1 block smaller
    uint64_t L(0), avg_D, next_D, i, this_timestamp(0), previous_timestamp(0);

    previous_timestamp = timestamps[0] - T;
    for (i = 1; i <= N; i++) {
      // Safely prevent out-of-sequence timestamps
      if (timestamps[i] > previous_timestamp) { this_timestamp = timestamps[i]; }
      else { this_timestamp = previous_timestamp + 1; }
      L += i * std::min<uint64_t>(6 * T, this_timestamp - previous_timestamp);
      previous_timestamp = this_timestamp;
    }
    if (L < N * N * T / 20) { L = N * N * T / 20; }
    avg_D = (cumulativeDifficulties[N] - cumulativeDifficulties[0]) / N;

    // Prevent round off error for small D and overflow for large D.
    if (avg_D > 2000000 * N * N * T) {
      next_D = (avg_D / (200 * L)) * (N * (N + 1) * T * 99);
    }
    else { next_D = (avg_D * N * (N + 1) * T * 99) / (200 * L); }

    // Optional. Make all insignificant digits zero for easy reading.
    i = 1000000000;
    while (i > 1) {
      if (next_D > i * 100) { next_D = ((next_D + i / 2) / i) * i; break; }
      else { i /= 10; }
    }

    // minimum limit
    if (!isTestnet() && next_D < 1000000) {
      //next_D = 1000000;
    }

    return next_D;
  }

	bool Currency::checkProofOfWork(Crypto::cn_context& context, const Block& block, difficulty_type currentDiffic, Crypto::Hash& proofOfWork) const {
    if (!get_block_longhash(context, block, proofOfWork)) {
      return false;
    }

    return check_hash(proofOfWork, currentDiffic);
	}

	size_t Currency::getApproximateMaximumInputCount(size_t transactionSize, size_t outputCount, size_t mixinCount) const {
		const size_t KEY_IMAGE_SIZE = sizeof(Crypto::KeyImage);
		const size_t OUTPUT_KEY_SIZE = sizeof(decltype(KeyOutput::key));
		const size_t AMOUNT_SIZE = sizeof(uint64_t) + 2; //varint
		const size_t GLOBAL_INDEXES_VECTOR_SIZE_SIZE = sizeof(uint8_t);//varint
		const size_t GLOBAL_INDEXES_INITIAL_VALUE_SIZE = sizeof(uint32_t);//varint
		const size_t GLOBAL_INDEXES_DIFFERENCE_SIZE = sizeof(uint32_t);//varint
		const size_t SIGNATURE_SIZE = sizeof(Crypto::Signature);
		const size_t EXTRA_TAG_SIZE = sizeof(uint8_t);
		const size_t INPUT_TAG_SIZE = sizeof(uint8_t);
		const size_t OUTPUT_TAG_SIZE = sizeof(uint8_t);
		const size_t PUBLIC_KEY_SIZE = sizeof(Crypto::PublicKey);
		const size_t TRANSACTION_VERSION_SIZE = sizeof(uint8_t);
		const size_t TRANSACTION_UNLOCK_TIME_SIZE = sizeof(uint64_t);

		const size_t outputsSize = outputCount * (OUTPUT_TAG_SIZE + OUTPUT_KEY_SIZE + AMOUNT_SIZE);
		const size_t headerSize = TRANSACTION_VERSION_SIZE + TRANSACTION_UNLOCK_TIME_SIZE + EXTRA_TAG_SIZE + PUBLIC_KEY_SIZE;
		const size_t inputSize = INPUT_TAG_SIZE + AMOUNT_SIZE + KEY_IMAGE_SIZE + SIGNATURE_SIZE + GLOBAL_INDEXES_VECTOR_SIZE_SIZE + GLOBAL_INDEXES_INITIAL_VALUE_SIZE +
			mixinCount * (GLOBAL_INDEXES_DIFFERENCE_SIZE + SIGNATURE_SIZE);

		return (transactionSize - headerSize - outputsSize) / inputSize;
	}

	CurrencyBuilder::CurrencyBuilder(Logging::ILogger& log) : m_currency(log) {
		maxBlockNumber(parameters::CRYPTONOTE_MAX_BLOCK_NUMBER);
		maxBlockBlobSize(parameters::CRYPTONOTE_MAX_BLOCK_BLOB_SIZE);
		maxTxSize(parameters::CRYPTONOTE_MAX_TX_SIZE);
		publicAddressBase58Prefix(parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
		minedMoneyUnlockWindow(parameters::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
		transactionSpendableAge(parameters::CRYPTONOTE_TX_SPENDABLE_AGE);
		expectedNumberOfBlocksPerDay(parameters::EXPECTED_NUMBER_OF_BLOCKS_PER_DAY);

		timestampCheckWindow(parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW);
		timestampCheckWindow_v1(parameters::BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1);
		blockFutureTimeLimit(parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT);
		blockFutureTimeLimit_v1(parameters::CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V1);

		moneySupply(parameters::MONEY_SUPPLY);
		emissionSpeedFactor(parameters::EMISSION_SPEED_FACTOR);
		cryptonoteCoinVersion(parameters::CRYPTONOTE_COIN_VERSION);

		rewardBlocksWindow(parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW);
		blockGrantedFullRewardZone(parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE);
		minerTxBlobReservedSize(parameters::CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE);
		maxTransactionSizeLimit(parameters::MAX_TRANSACTION_SIZE_LIMIT);

		minMixin(parameters::MIN_TX_MIXIN_SIZE);
		maxMixin(parameters::MAX_TX_MIXIN_SIZE);

		numberOfDecimalPlaces(parameters::CRYPTONOTE_DISPLAY_DECIMAL_POINT);

		minimumFee(parameters::MINIMUM_FEE);

    depositMinAmount(parameters::DEPOSIT_MIN_AMOUNT);
    depositMinTerm(parameters::DEPOSIT_MIN_TERM);
    depositMaxTerm(parameters::DEPOSIT_MAX_TERM);
    depositMinTotalRateFactor(parameters::DEPOSIT_MIN_TOTAL_RATE_FACTOR);
    depositMaxTotalRate(parameters::DEPOSIT_MAX_TOTAL_RATE);

		defaultDustThreshold(parameters::DEFAULT_DUST_THRESHOLD);

		difficultyTarget(parameters::DIFFICULTY_TARGET);
		difficultyWindow(parameters::DIFFICULTY_WINDOW);
		difficultyLag(parameters::DIFFICULTY_LAG);
		difficultyCut(parameters::DIFFICULTY_CUT);

		maxBlockSizeInitial(parameters::MAX_BLOCK_SIZE_INITIAL);
		maxBlockSizeGrowthSpeedNumerator(parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_NUMERATOR);
		maxBlockSizeGrowthSpeedDenominator(parameters::MAX_BLOCK_SIZE_GROWTH_SPEED_DENOMINATOR);

		lockedTxAllowedDeltaSeconds(parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS);
		lockedTxAllowedDeltaBlocks(parameters::CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS);

		mempoolTxLiveTime(parameters::CRYPTONOTE_MEMPOOL_TX_LIVETIME);
		mempoolTxFromAltBlockLiveTime(parameters::CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME);
		numberOfPeriodsToForgetTxDeletedFromPool(parameters::CRYPTONOTE_NUMBER_OF_PERIODS_TO_FORGET_TX_DELETED_FROM_POOL);

		upgradeHeightV2(parameters::UPGRADE_HEIGHT_V2);
		upgradeHeightV3(parameters::UPGRADE_HEIGHT_V3);
		upgradeHeightV4(parameters::UPGRADE_HEIGHT_V4);
		upgradeHeightV5(parameters::UPGRADE_HEIGHT_V5);
		upgradeVotingThreshold(parameters::UPGRADE_VOTING_THRESHOLD);
		upgradeVotingWindow(parameters::UPGRADE_VOTING_WINDOW);
		upgradeWindow(parameters::UPGRADE_WINDOW);

		blocksFileName(parameters::CRYPTONOTE_BLOCKS_FILENAME);
		blocksCacheFileName(parameters::CRYPTONOTE_BLOCKSCACHE_FILENAME);
		blockIndexesFileName(parameters::CRYPTONOTE_BLOCKINDEXES_FILENAME);
		txPoolFileName(parameters::CRYPTONOTE_POOLDATA_FILENAME);
		blockchainIndicesFileName(parameters::CRYPTONOTE_BLOCKCHAIN_INDICES_FILENAME);

		testnet(false);
	}

	Transaction CurrencyBuilder::generateGenesisTransaction() {
		CryptoNote::Transaction tx;
		CryptoNote::AccountPublicAddress ac = boost::value_initialized<CryptoNote::AccountPublicAddress>();
		m_currency.constructMinerTx(1, 0, 0, 0, 0, 0, ac, tx, BinaryArray(), 1); // zero fee in genesis
		return tx;
	}
	CurrencyBuilder& CurrencyBuilder::emissionSpeedFactor(unsigned int val) {
		if (val <= 0 || val > 8 * sizeof(uint64_t)) {
			throw std::invalid_argument("val at emissionSpeedFactor()");
		}

		m_currency.m_emissionSpeedFactor = val;
		return *this;
	}

	CurrencyBuilder& CurrencyBuilder::numberOfDecimalPlaces(size_t val) {
		m_currency.m_numberOfDecimalPlaces = val;
		m_currency.m_coin = 1;
		for (size_t i = 0; i < m_currency.m_numberOfDecimalPlaces; ++i) {
			m_currency.m_coin *= 10;
		}

		return *this;
	}

	CurrencyBuilder& CurrencyBuilder::difficultyWindow(size_t val) {
		if (val < 2) {
			throw std::invalid_argument("val at difficultyWindow()");
		}
		m_currency.m_difficultyWindow = val;
		return *this;
	}

	CurrencyBuilder& CurrencyBuilder::upgradeVotingThreshold(unsigned int val) {
		if (val <= 0 || val > 100) {
			throw std::invalid_argument("val at upgradeVotingThreshold()");
		}

		m_currency.m_upgradeVotingThreshold = val;
		return *this;
	}

	CurrencyBuilder& CurrencyBuilder::upgradeWindow(size_t val) {
		if (val <= 0) {
			throw std::invalid_argument("val at upgradeWindow()");
		}

		m_currency.m_upgradeWindow = static_cast<uint32_t>(val);
		return *this;
	}

}

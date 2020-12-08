// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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

#pragma once

#include "INode.h"
// #include "WalletSynchronizationContext.h"
#include "WalletLegacy/WalletSendTransactionContext.h"
#include "WalletLegacy/WalletLegacyEvent.h"
#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteTools.h"

#if defined __linux__ && !defined __ANDROID__
#define BOOST_NO_CXX11_SCOPED_ENUMS
#endif
#include <boost/filesystem.hpp>
#if defined __linux__ && !defined __ANDROID__
#undef BOOST_NO_CXX11_SCOPED_ENUMS
#endif

#include <deque>
#include <functional>
#include <memory>

namespace CryptoNote {

class WalletRequest
{
public:
  typedef std::function<void(std::deque<std::shared_ptr<WalletLegacyEvent>>& events, boost::optional<std::shared_ptr<WalletRequest> >& nextRequest, std::error_code ec)> Callback;

  virtual ~WalletRequest() {};

  virtual void perform(INode& node, std::function<void (WalletRequest::Callback, std::error_code)> cb) = 0;

};

class WalletGetRandomOutsByAmountsRequest: public WalletRequest
{
public:
  WalletGetRandomOutsByAmountsRequest(const std::vector<uint64_t>& amounts, uint64_t outsCount, std::shared_ptr<SendTransactionContext> context, Callback cb) :
    m_amounts(amounts), m_outsCount(outsCount), m_context(context), m_cb(cb) {};

  virtual ~WalletGetRandomOutsByAmountsRequest() {};

  virtual void perform(INode& node, std::function<void (WalletRequest::Callback, std::error_code)> cb) override
  {
    node.getRandomOutsByAmounts(std::move(m_amounts), m_outsCount, std::ref(m_context->outs), std::bind(cb, m_cb, std::placeholders::_1));
  };

private:
  std::vector<uint64_t> m_amounts;
  uint64_t m_outsCount;
  std::shared_ptr<SendTransactionContext> m_context;
  Callback m_cb;
};

class WalletRelayTransactionRequest: public WalletRequest
{
public:
  WalletRelayTransactionRequest(const CryptoNote::Transaction& tx, Callback cb, bool do_not_relay) : m_tx(tx), m_cb(cb), m_do_not_relay(do_not_relay) {};
  virtual ~WalletRelayTransactionRequest() {};

  inline void dumpTransaction(const INode::Callback& callback) {
    const std::string filename = "raw_tx.txt";
    boost::system::error_code ec;
    if (boost::filesystem::exists(filename, ec)) {
      boost::filesystem::remove(filename, ec);
    }
    std::ofstream txFile(filename, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!txFile.good()) {
      throw;
    }

    std::string tx_as_hex = Common::toHex(toBinaryArray(m_tx));

    txFile << tx_as_hex;

    callback(std::error_code());
  }

  virtual void perform(INode& node, std::function<void (WalletRequest::Callback, std::error_code)> cb) override
  {
    if (!m_do_not_relay)
      node.relayTransaction(m_tx, std::bind(cb, m_cb, std::placeholders::_1));
    else
      dumpTransaction(std::bind(cb, m_cb, std::placeholders::_1));
  }

private:
  CryptoNote::Transaction m_tx;
  Callback m_cb;
  bool m_do_not_relay;
};

} //namespace CryptoNote

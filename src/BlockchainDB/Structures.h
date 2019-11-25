#ifndef STRUCTURES_H
#define STRUCTURES_H

#include "CryptoNoteCore/TransactionPool.h"

#pragma once
namespace CryptoNote {
#pragma pack(push, 1)
struct output_data_t
{
  Crypto::PublicKey pubkey;       //!< the output's public key (for spend verification)
  uint64_t           unlock_time;  //!< the output's unlock time (or height)
  uint64_t           height;       //!< the height of the block which created the output
};
#pragma pack(pop)

#pragma pack(push, 1)
struct tx_data_t
{
  uint64_t tx_id;
  uint64_t unlock_time;
  uint64_t block_id;
};
#pragma pack(pop)

struct txpool_tx_meta_t
{
  Crypto::Hash max_used_block_id;
  Crypto::Hash last_failed_id;
  uint64_t blob_size;
  uint64_t fee;
  uint64_t max_used_block_height;
  uint64_t last_failed_height;
  uint64_t receive_time;
  uint64_t last_relayed_time;
  // 112 bytes
  uint8_t kept_by_block;
  uint8_t relayed;
  uint8_t do_not_relay;
  uint8_t double_spend_seen: 1;

  uint8_t padding[76]; // till 192 bytes
};
}

typedef std::pair<Crypto::Hash, uint64_t> tx_out_index;
#endif // STRUCTURES_H

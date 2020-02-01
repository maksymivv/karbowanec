// Copyright (c) 2019 fireice-uk
// Copyright (c) 2019 The Circle Foundation
// Copyright (c) 2020, The Karbo Developers
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "cryptonight.hpp"

namespace Crypto {

void cn_slow_hash(cn_context &context, const void *data, size_t length, Hash &hash) {
	if(hw_check_aes())
		cryptonight_hash<true, CRYPTONIGHT>(data, length, reinterpret_cast<char *>(&hash), context);
	else
		cryptonight_hash<false, CRYPTONIGHT>(data, length, reinterpret_cast<char *>(&hash), context);
}

void cn_slow_hash_k(cn_context &context, const void *data, size_t length, Hash &hash) {
	if(hw_check_aes())
		cryptonight_hash<true, CRYPTONIGHT_KRB>(data, length, reinterpret_cast<char *>(&hash), context);
	else
		cryptonight_hash<false, CRYPTONIGHT_KRB>(data, length, reinterpret_cast<char *>(&hash), context);
}

}
// Copyright (c) 2019 fireice-uk
// Copyright (c) 2019 The Circle Foundation
// Copyright (c) 2020, The Karbo Developers
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

enum cryptonight_algo : size_t
{
	CRYPTONIGHT,
	CRYPTONIGHT_KRB
};

constexpr size_t CRYPTONIGHT_MEMORY = 2 * 1024 * 1024;

constexpr uint32_t CRYPTONIGHT_MASK = 0x1FFFF0;
constexpr uint32_t CRYPTONIGHT_KRB_MASK = 0x1FFFC0;

constexpr uint32_t CRYPTONIGHT_ITER = 0x80000;
constexpr uint32_t CRYPTONIGHT_KRB_ITER = 0x8000;

template<cryptonight_algo ALGO>
inline constexpr size_t cn_select_memory() { return 0; }

template<>
inline constexpr size_t cn_select_memory<CRYPTONIGHT>() { return CRYPTONIGHT_MEMORY; }

template<>
inline constexpr size_t cn_select_memory<CRYPTONIGHT_KRB>() { return CRYPTONIGHT_MEMORY; }


inline size_t cn_select_memory(cryptonight_algo algo)
{
	switch(algo)
	{
	case CRYPTONIGHT:
		return CRYPTONIGHT_MEMORY;
	case CRYPTONIGHT_KRB:
		return CRYPTONIGHT_MEMORY;
	default:
		return 0;
	}
}

template<cryptonight_algo ALGO>
inline constexpr uint32_t cn_select_mask() { return 0; }

template<>
inline constexpr uint32_t cn_select_mask<CRYPTONIGHT>() { return CRYPTONIGHT_MASK; }

template<>
inline constexpr uint32_t cn_select_mask<CRYPTONIGHT_KRB>() { return CRYPTONIGHT_KRB_MASK; }

inline size_t cn_select_mask(cryptonight_algo algo)
{
	switch(algo)
	{
	case CRYPTONIGHT:
		return CRYPTONIGHT_MASK;
	case CRYPTONIGHT_KRB:
		return CRYPTONIGHT_KRB_MASK;
	default:
		return 0;
	}
}

template<cryptonight_algo ALGO>
inline constexpr uint32_t cn_select_iter() { return 0; }

template<>
inline constexpr uint32_t cn_select_iter<CRYPTONIGHT>() { return CRYPTONIGHT_ITER; }

template<>
inline constexpr uint32_t cn_select_iter<CRYPTONIGHT_KRB>() { return CRYPTONIGHT_KRB_ITER; }

inline size_t cn_select_iter(cryptonight_algo algo)
{
	switch(algo)
	{
	case CRYPTONIGHT:
		return CRYPTONIGHT_ITER;
	case CRYPTONIGHT_KRB:
		return CRYPTONIGHT_KRB_ITER;
	default:
		return 0;
	}
}
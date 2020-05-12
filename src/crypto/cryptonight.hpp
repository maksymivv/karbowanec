// Copyright (c) 2019 fireice-uk
// Copyright (c) 2019 The Circle Foundation
// Copyright (c) 2020, The Karbo Developers
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once
#include <string.h>
#include <fenv.h>

#include "keccak.h"
#include "hash.h"
#include "cn_aux.hpp"
#include "aux_hash.h"

#if !defined(_LP64) && !defined(_WIN64)
#error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

namespace Crypto {

inline void set_float_rounding_mode_nearest() {
#ifdef _MSC_VER
	_control87(RC_NEAR, MCW_RC);
#else
	fesetround(FE_TONEAREST);
#endif
}

template<bool SOFT_AES>
inline void aes_genkey(const __m128i* memory, __m128i& k0, __m128i& k1, __m128i& k2, __m128i& k3,
	__m128i& k4, __m128i& k5, __m128i& k6, __m128i& k7, __m128i& k8, __m128i& k9)
{
	__m128i xout0, xout1, xout2;

	xout0 = _mm_load_si128(memory);
	xout2 = _mm_load_si128(memory+1);
	k0 = xout0;
	k1 = xout2;

	if(SOFT_AES)
		xout1 = soft_aeskeygenassist<0x01>(xout2);
	else
		xout1 = _mm_aeskeygenassist_si128(xout2, 0x01);

	xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
	xout0 = sl_xor(xout0);
	xout0 = _mm_xor_si128(xout0, xout1);

	if(SOFT_AES)
		xout1 = soft_aeskeygenassist<0x00>(xout0);
	else
		xout1 = _mm_aeskeygenassist_si128(xout0, 0x00);

	xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
	xout2 = sl_xor(xout2);
	xout2 = _mm_xor_si128(xout2, xout1);
	k2 = xout0;
	k3 = xout2;

	if(SOFT_AES)
		xout1 = soft_aeskeygenassist<0x02>(xout2);
	else
		xout1 = _mm_aeskeygenassist_si128(xout2, 0x02);

	xout1 = _mm_shuffle_epi32(xout1, 0xFF);
	xout0 = sl_xor(xout0);
	xout0 = _mm_xor_si128(xout0, xout1);

	if(SOFT_AES)
		xout1 = soft_aeskeygenassist<0x00>(xout0);
	else
		xout1 = _mm_aeskeygenassist_si128(xout0, 0x00);

	xout1 = _mm_shuffle_epi32(xout1, 0xAA);
	xout2 = sl_xor(xout2);
	xout2 = _mm_xor_si128(xout2, xout1);
	k4 = xout0;
	k5 = xout2;

	if(SOFT_AES)
		xout1 = soft_aeskeygenassist<0x04>(xout2);
	else
		xout1 = _mm_aeskeygenassist_si128(xout2, 0x04);

	xout1 = _mm_shuffle_epi32(xout1, 0xFF);
	xout0 = sl_xor(xout0);
	xout0 = _mm_xor_si128(xout0, xout1);

	if(SOFT_AES)
		xout1 = soft_aeskeygenassist<0x00>(xout0);
	else
		xout1 = _mm_aeskeygenassist_si128(xout0, 0x00);

	xout1 = _mm_shuffle_epi32(xout1, 0xAA);
	xout2 = sl_xor(xout2);
	xout2 = _mm_xor_si128(xout2, xout1);
	k6 = xout0;
	k7 = xout2;

	if(SOFT_AES)
		xout1 = soft_aeskeygenassist<0x08>(xout2);
	else
		xout1 = _mm_aeskeygenassist_si128(xout2, 0x08);

	xout1 = _mm_shuffle_epi32(xout1, 0xFF);
	xout0 = sl_xor(xout0);
	xout0 = _mm_xor_si128(xout0, xout1);

	if(SOFT_AES)
		xout1 = soft_aeskeygenassist<0x00>(xout0);
	else
		xout1 = _mm_aeskeygenassist_si128(xout0, 0x00);

	xout1 = _mm_shuffle_epi32(xout1, 0xAA);
	xout2 = sl_xor(xout2);
	xout2 = _mm_xor_si128(xout2, xout1);
	k8 = xout0;
	k9 = xout2;
}

inline void xor_shift(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7)
{
		__m128i tmp0 = x0;
		x0 = _mm_xor_si128(x0, x1);
		x1 = _mm_xor_si128(x1, x2);
		x2 = _mm_xor_si128(x2, x3);
		x3 = _mm_xor_si128(x3, x4);
		x4 = _mm_xor_si128(x4, x5);
		x5 = _mm_xor_si128(x5, x6);
		x6 = _mm_xor_si128(x6, x7);
		x7 = _mm_xor_si128(x7, tmp0);
}

template<bool SOFT_AES, size_t MEMORY, cryptonight_algo ALGO>
void cn_explode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(input, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

	xin0 = _mm_load_si128(input + 4);
	xin1 = _mm_load_si128(input + 5);
	xin2 = _mm_load_si128(input + 6);
	xin3 = _mm_load_si128(input + 7);
	xin4 = _mm_load_si128(input + 8);
	xin5 = _mm_load_si128(input + 9);
	xin6 = _mm_load_si128(input + 10);
	xin7 = _mm_load_si128(input + 11);

	// Note, this loop is only executed if ALGO > 0
	for (size_t i = 0; ALGO > 0 && i < 16; i++)
	{
		aes_round<SOFT_AES>(k0, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k1, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k2, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k3, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k4, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k5, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k6, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k7, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k8, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k9, xin0, xin1, xin1, xin3, xin4, xin5, xin6, xin7);

		xor_shift(xin0, xin1, xin1, xin3, xin4, xin5, xin6, xin7);
	}

	for (size_t i = 0; i < MEMORY / sizeof(__m128i); i += 8)
	{
		aes_round<SOFT_AES>(k0, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k1, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k2, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k3, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k4, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k5, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k6, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k7, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k8, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
		aes_round<SOFT_AES>(k9, xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);

		_mm_store_si128(output + i + 0, xin0);
		_mm_store_si128(output + i + 1, xin1);
		_mm_store_si128(output + i + 2, xin2);
		_mm_store_si128(output + i + 3, xin3);
		_mm_store_si128(output + i + 4, xin4);
		_mm_store_si128(output + i + 5, xin5);
		_mm_store_si128(output + i + 6, xin6);
		_mm_store_si128(output + i + 7, xin7);
	}
}

template<bool SOFT_AES, size_t MEMORY, cryptonight_algo ALGO>
void cn_implode_scratchpad(const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey<SOFT_AES>(output + 2, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

	xout0 = _mm_load_si128(output + 4);
	xout1 = _mm_load_si128(output + 5);
	xout2 = _mm_load_si128(output + 6);
	xout3 = _mm_load_si128(output + 7);
	xout4 = _mm_load_si128(output + 8);
	xout5 = _mm_load_si128(output + 9);
	xout6 = _mm_load_si128(output + 10);
	xout7 = _mm_load_si128(output + 11);

	for (size_t i = 0; i < MEMORY / sizeof(__m128i); i += 8)
	{
		xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
		xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
		xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
		xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
		xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
		xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
		xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
		xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

		aes_round<SOFT_AES>(k0, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k1, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k2, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k3, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k4, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k5, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k6, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k7, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k8, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k9, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);

		if (ALGO > 0)
			xor_shift(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
	}

	// Note, this loop is only executed if ALGO > 0
	for (size_t i = 0; ALGO > 0 && i < MEMORY / sizeof(__m128i); i += 8)
	{
		xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
		xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
		xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
		xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
		xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
		xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
		xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
		xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

		aes_round<SOFT_AES>(k0, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k1, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k2, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k3, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k4, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k5, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k6, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k7, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k8, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k9, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);

		xor_shift(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
	}

	// Note, this loop is only executed if ALGO > 0
	for (size_t i = 0; ALGO > 0 && i < 16; i++)
	{
		aes_round<SOFT_AES>(k0, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k1, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k2, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k3, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k4, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k5, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k6, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k7, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k8, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
		aes_round<SOFT_AES>(k9, xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);

		xor_shift(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
	}

	_mm_store_si128(output + 4, xout0);
	_mm_store_si128(output + 5, xout1);
	_mm_store_si128(output + 6, xout2);
	_mm_store_si128(output + 7, xout3);
	_mm_store_si128(output + 8, xout4);
	_mm_store_si128(output + 9, xout5);
	_mm_store_si128(output + 10, xout6);
	_mm_store_si128(output + 11, xout7);
}

inline __m128 _mm_set1_ps_epi32(uint32_t x)
{
	return _mm_castsi128_ps(_mm_set1_epi32(x));
}

template<bool SOFT_AES, cryptonight_algo ALGO>
void cryptonight_hash(const void* input, size_t len, void* output, cn_context& ctx0)
{
	set_float_rounding_mode_nearest();

	constexpr size_t MEMORY = cn_select_memory<ALGO>();
	constexpr uint32_t MASK = cn_select_mask<ALGO>();
	constexpr uint32_t ITER = cn_select_iter<ALGO>();

	keccak((const uint8_t *)input, static_cast<uint8_t>(len), ctx0.hash_state, 200);

	// Optim - 99% time boundary
	cn_explode_scratchpad<SOFT_AES, MEMORY, ALGO>((__m128i*)ctx0.hash_state, (__m128i*)ctx0.long_state);

	uint8_t* l0 = ctx0.long_state;
	uint64_t* h0 = (uint64_t*)ctx0.hash_state;

	uint64_t al0 = h0[0] ^ h0[4];
	uint64_t ah0 = h0[1] ^ h0[5];
	__m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
	__m128 conc_var = _mm_setzero_ps();

	uint64_t idx0 = h0[0] ^ h0[4];
	// Optim - 90% time boundary
	for(size_t i = 0; i < ITER; i++)
	{
		__m128i cx;
		
		cx = _mm_load_si128((__m128i *)&l0[idx0 & MASK]);

		__m128i ax0 = _mm_set_epi64x(ah0, al0);
		if (SOFT_AES)
			cx = soft_aesenc(cx, ax0);
		else
			cx = _mm_aesenc_si128(cx, ax0);

		if (ALGO > 0)
		{
			while ((_mm_cvtsi128_si32(cx) & 0xf) != 0)
			{
				cx = _mm_xor_si128(cx, bx0);
				__m128d da = _mm_cvtepi32_pd(cx);
				__m128d db = _mm_cvtepi32_pd(_mm_shuffle_epi32(cx, _MM_SHUFFLE(0, 1, 2, 3)));
				da = _mm_mul_pd(da, db);
				if (SOFT_AES)
					cx = soft_aesenc(_mm_castpd_si128(da), ax0);
				else
					cx = _mm_aesenc_si128(_mm_castpd_si128(da), ax0);
			}
			if (SOFT_AES)
				cx = soft_aesenc(cx, ax0);
			else
				cx = _mm_aesenc_si128(cx, ax0);
		}

		_mm_store_si128((__m128i *)&l0[idx0 & MASK], _mm_xor_si128(bx0, cx));

		idx0 = _mm_cvtsi128_si64(cx);
		bx0 = cx;

		uint64_t hi, lo, cl, ch;
		cl = ((uint64_t*)&l0[idx0 & MASK])[0];
		ch = ((uint64_t*)&l0[idx0 & MASK])[1];

		lo = _umul128(idx0, cl, &hi);
		al0 += hi;
		ah0 += lo;

		((uint64_t*)&l0[idx0 & MASK])[0] = al0;

		((uint64_t*)&l0[idx0 & MASK])[1] = ah0;

		ah0 ^= ch;
		al0 ^= cl;
		idx0 = al0;
	}

	// Optim - 90% time boundary
	cn_implode_scratchpad<SOFT_AES, MEMORY, ALGO>((__m128i*)ctx0.long_state, (__m128i*)ctx0.hash_state);

	// Optim - 99% time boundary

	keccakf((uint64_t*)ctx0.hash_state);

	switch(ctx0.hash_state[0] & 3)
	{
	case 0:
		blake256_hash(ctx0.hash_state, (uint8_t*)output);
		break;
	case 1:
		groestl_hash(ctx0.hash_state, (uint8_t*)output);
		break;
	case 2:
		jh_hash(ctx0.hash_state, (uint8_t*)output);
		break;
	case 3:
		skein_hash(ctx0.hash_state, (uint8_t*)output);
		break;
	}
}

}

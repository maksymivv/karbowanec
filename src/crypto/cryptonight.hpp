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

#if defined(__ARM_FEATURE_SIMD32) || defined(__ARM_NEON)
#include "sse2neon.h"
#endif 

// WTF??
#if !defined(_LP64) && !defined(_WIN64) && (!defined(__ARM_FEATURE_SIMD32) || !defined(__ARM_NEON))
#error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

namespace Crypto {

enum cryptonight_algo : size_t
{
  CRYPTONIGHT,
  CRYPTONIGHT_GPU,
  CRYPTONIGHT_KRB
};

constexpr uint32_t CRYPTONIGHT_MASK     = 0x1FFFF0;
constexpr uint32_t CRYPTONIGHT_GPU_MASK = 0x1FFFC0;

constexpr uint32_t CRYPTONIGHT_ITER     = 0x80000;
constexpr uint32_t CRYPTONIGHT_GPU_ITER = 0xC000;
constexpr uint32_t CRYPTONIGHT_KRB_ITER = 0x8000;

inline void set_float_rounding_mode_nearest() {
#ifdef _MSC_VER
	_control87(RC_NEAR, MCW_RC);
#else
	std::fesetround(FE_TONEAREST);
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

	constexpr uint32_t MASK = ALGO > 0 ? CRYPTONIGHT_GPU_MASK : CRYPTONIGHT_MASK;
	constexpr uint32_t ITER = ALGO == 0 ? CRYPTONIGHT_ITER : CRYPTONIGHT_KRB_ITER;

	keccak((const uint8_t *)input, static_cast<uint8_t>(len), ctx0.hash_state, 200);

	// Optim - 99% time boundary
	cn_explode_scratchpad<SOFT_AES, CRYPTONIGHT_MEMORY, ALGO>((__m128i*)ctx0.hash_state, (__m128i*)ctx0.long_state);

	uint8_t* l0 = ctx0.long_state;
	uint64_t* h0 = (uint64_t*)ctx0.hash_state;

	uint64_t al0 = h0[0] ^ h0[4];
	uint64_t ah0 = h0[1] ^ h0[5];
	__m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

	uint64_t idx0 = h0[0] ^ h0[4];
	// Optim - 90% time boundary
	for(size_t i = 0; i < ITER; i++)
	{
		__m128i cx;
		cx = _mm_load_si128((__m128i *)&l0[idx0 & MASK]);

		__m128i ax0 = _mm_set_epi64x(ah0, al0);
    if (SOFT_AES) {
      cx = soft_aesenc(cx, ax0);
    }
    else {
#if !defined(ARM)
      cx = _mm_aesenc_si128(cx, ax0);
#endif
    }

		if (ALGO == 2)
		{
			while ((_mm_cvtsi128_si32(cx) & 0xf) != 0)
			{
				cx = _mm_xor_si128(cx, bx0);
				__m128d da = _mm_cvtepi32_pd(cx);
				__m128d db = _mm_cvtepi32_pd(_mm_shuffle_epi32(cx, _MM_SHUFFLE(0, 1, 2, 3)));
				da = _mm_mul_pd(da, db);
        if (SOFT_AES) {
          cx = soft_aesenc(_mm_castpd_si128(da), ax0);
        }
        else {
#if !defined(ARM)
          cx = _mm_aesenc_si128(_mm_castpd_si128(da), ax0);
#endif
        }
			}
      if (SOFT_AES) {
        cx = soft_aesenc(cx, ax0);
      }
      else {
#if !defined(ARM)
        cx = _mm_aesenc_si128(cx, ax0);
#endif
      }
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
	cn_implode_scratchpad<SOFT_AES, CRYPTONIGHT_MEMORY, ALGO>((__m128i*)ctx0.long_state, (__m128i*)ctx0.hash_state);

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

inline void cn_explode_scratchpad_gpu(const uint8_t* input, uint8_t* output, const size_t mem)
{
  constexpr size_t hash_size = 200; // 25x8 bytes
  alignas(128) uint64_t hash[25];

  for (uint64_t i = 0; i < mem / 512; i++)
  {
    memcpy(hash, input, hash_size);
    hash[0] ^= i;

    keccakf(hash);
    memcpy(output, hash, 160);
    output += 160;

    keccakf(hash);
    memcpy(output, hash, 176);
    output += 176;

    keccakf(hash);
    memcpy(output, hash, 176);
    output += 176;
  }
}

inline void prep_dv(__m128i* idx, __m128i& v, __m128& n)
{
	v = _mm_load_si128(idx);
	n = _mm_cvtepi32_ps(v);
}

inline __m128 fma_break(__m128 x)
{
	// Break the dependency chain by setitng the exp to ?????01
	x = _mm_and_ps(_mm_castsi128_ps(_mm_set1_epi32(0xFEFFFFFF)), x);
	return _mm_or_ps(_mm_castsi128_ps(_mm_set1_epi32(0x00800000)), x);
}

// 14
inline void sub_round(__m128 n0, __m128 n1, __m128 n2, __m128 n3, __m128 rnd_c, __m128& n, __m128& d, __m128& c)
{
	n1 = _mm_add_ps(n1, c);
	__m128 nn = _mm_mul_ps(n0, c);
	nn = _mm_mul_ps(n1, _mm_mul_ps(nn, nn));
	nn = fma_break(nn);
	n = _mm_add_ps(n, nn);

	n3 = _mm_sub_ps(n3, c);
	__m128 dd = _mm_mul_ps(n2, c);
	dd = _mm_mul_ps(n3, _mm_mul_ps(dd, dd));
	dd = fma_break(dd);
	d = _mm_add_ps(d, dd);

	//Constant feedback
	c = _mm_add_ps(c, rnd_c);
	c = _mm_add_ps(c, _mm_set1_ps(0.734375f));
	__m128 r = _mm_add_ps(nn, dd);
	r = _mm_and_ps(_mm_castsi128_ps(_mm_set1_epi32(0x807FFFFF)), r);
	r = _mm_or_ps(_mm_castsi128_ps(_mm_set1_epi32(0x40000000)), r);
	c = _mm_add_ps(c, r);
}

// 14*8 + 2 = 112
inline void round_compute(__m128 n0, __m128 n1, __m128 n2, __m128 n3, __m128 rnd_c, __m128& c, __m128& r)
{
	__m128 n = _mm_setzero_ps(), d = _mm_setzero_ps();

	sub_round(n0, n1, n2, n3, rnd_c, n, d, c);
	sub_round(n1, n2, n3, n0, rnd_c, n, d, c);
	sub_round(n2, n3, n0, n1, rnd_c, n, d, c);
	sub_round(n3, n0, n1, n2, rnd_c, n, d, c);
	sub_round(n3, n2, n1, n0, rnd_c, n, d, c);
	sub_round(n2, n1, n0, n3, rnd_c, n, d, c);
	sub_round(n1, n0, n3, n2, rnd_c, n, d, c);
	sub_round(n0, n3, n2, n1, rnd_c, n, d, c);

	// Make sure abs(d) > 2.0 - this prevents division by zero and accidental overflows by division by < 1.0
	d = _mm_and_ps(_mm_castsi128_ps(_mm_set1_epi32(0xFF7FFFFF)), d);
	d = _mm_or_ps(_mm_castsi128_ps(_mm_set1_epi32(0x40000000)), d);
	r = _mm_add_ps(r, _mm_div_ps(n, d));
}

// 112×4 = 448
template <bool add>
inline __m128i single_compute(__m128 n0, __m128 n1, __m128 n2, __m128 n3, float cnt, __m128 rnd_c, __m128& sum)
{
	__m128 c = _mm_set1_ps(cnt);
	__m128 r = _mm_setzero_ps();

	round_compute(n0, n1, n2, n3, rnd_c, c, r);
	round_compute(n0, n1, n2, n3, rnd_c, c, r);
	round_compute(n0, n1, n2, n3, rnd_c, c, r);
	round_compute(n0, n1, n2, n3, rnd_c, c, r);

	// do a quick fmod by setting exp to 2
	r = _mm_and_ps(_mm_castsi128_ps(_mm_set1_epi32(0x807FFFFF)), r);
	r = _mm_or_ps(_mm_castsi128_ps(_mm_set1_epi32(0x40000000)), r);

	if (add)
		sum = _mm_add_ps(sum, r);
	else
		sum = r;

	r = _mm_mul_ps(r, _mm_set1_ps(536870880.0f)); // 35
	return _mm_cvttps_epi32(r);
}

template <size_t rot>
inline void single_compute_wrap(__m128 n0, __m128 n1, __m128 n2, __m128 n3, float cnt, __m128 rnd_c, __m128& sum, __m128i& out)
{
	__m128i r = single_compute<rot % 2 != 0>(n0, n1, n2, n3, cnt, rnd_c, sum);
	if (rot != 0)
		r = _mm_or_si128(_mm_slli_si128(r, 16 - rot), _mm_srli_si128(r, rot));
	out = _mm_xor_si128(out, r);
}

inline __m128i* scratchpad_ptr(uint8_t* lpad, uint32_t idx, size_t n, const uint32_t mask) { return reinterpret_cast<__m128i*>(lpad + (idx & mask) + n * 16); }

inline void cn_gpu_inner_ssse3(const uint8_t* spad, uint8_t* lpad)
{
	const uint32_t ITER = CRYPTONIGHT_GPU_ITER;
	const uint32_t mask = CRYPTONIGHT_GPU_MASK;

	uint32_t s = reinterpret_cast<const uint32_t*>(spad)[0] >> 8;
	__m128i* idx0 = scratchpad_ptr(lpad, s, 0, mask);
	__m128i* idx1 = scratchpad_ptr(lpad, s, 1, mask);
	__m128i* idx2 = scratchpad_ptr(lpad, s, 2, mask);
	__m128i* idx3 = scratchpad_ptr(lpad, s, 3, mask);
	__m128 sum0 = _mm_setzero_ps();

	for (size_t i = 0; i < ITER; i++)
	{
		__m128 n0, n1, n2, n3;
		__m128i v0, v1, v2, v3;
		__m128 suma, sumb, sum1, sum2, sum3;

		prep_dv(idx0, v0, n0);
		prep_dv(idx1, v1, n1);
		prep_dv(idx2, v2, n2);
		prep_dv(idx3, v3, n3);
		__m128 rc = sum0;

		__m128i out, out2;
		out = _mm_setzero_si128();
		single_compute_wrap<0>(n0, n1, n2, n3, 1.3437500f, rc, suma, out);
		single_compute_wrap<1>(n0, n2, n3, n1, 1.2812500f, rc, suma, out);
		single_compute_wrap<2>(n0, n3, n1, n2, 1.3593750f, rc, sumb, out);
		single_compute_wrap<3>(n0, n3, n2, n1, 1.3671875f, rc, sumb, out);
		sum0 = _mm_add_ps(suma, sumb);
		_mm_store_si128(idx0, _mm_xor_si128(v0, out));
		out2 = out;

		out = _mm_setzero_si128();
		single_compute_wrap<0>(n1, n0, n2, n3, 1.4296875f, rc, suma, out);
		single_compute_wrap<1>(n1, n2, n3, n0, 1.3984375f, rc, suma, out);
		single_compute_wrap<2>(n1, n3, n0, n2, 1.3828125f, rc, sumb, out);
		single_compute_wrap<3>(n1, n3, n2, n0, 1.3046875f, rc, sumb, out);
		sum1 = _mm_add_ps(suma, sumb);
		_mm_store_si128(idx1, _mm_xor_si128(v1, out));
		out2 = _mm_xor_si128(out2, out);

		out = _mm_setzero_si128();
		single_compute_wrap<0>(n2, n1, n0, n3, 1.4140625f, rc, suma, out);
		single_compute_wrap<1>(n2, n0, n3, n1, 1.2734375f, rc, suma, out);
		single_compute_wrap<2>(n2, n3, n1, n0, 1.2578125f, rc, sumb, out);
		single_compute_wrap<3>(n2, n3, n0, n1, 1.2890625f, rc, sumb, out);
		sum2 = _mm_add_ps(suma, sumb);
		_mm_store_si128(idx2, _mm_xor_si128(v2, out));
		out2 = _mm_xor_si128(out2, out);

		out = _mm_setzero_si128();
		single_compute_wrap<0>(n3, n1, n2, n0, 1.3203125f, rc, suma, out);
		single_compute_wrap<1>(n3, n2, n0, n1, 1.3515625f, rc, suma, out);
		single_compute_wrap<2>(n3, n0, n1, n2, 1.3359375f, rc, sumb, out);
		single_compute_wrap<3>(n3, n0, n2, n1, 1.4609375f, rc, sumb, out);
		sum3 = _mm_add_ps(suma, sumb);
		_mm_store_si128(idx3, _mm_xor_si128(v3, out));
		out2 = _mm_xor_si128(out2, out);
		sum0 = _mm_add_ps(sum0, sum1);
		sum2 = _mm_add_ps(sum2, sum3);
		sum0 = _mm_add_ps(sum0, sum2);

		sum0 = _mm_and_ps(_mm_castsi128_ps(_mm_set1_epi32(0x7fffffff)), sum0); // take abs(va) by masking the float sign bit
		// vs range 0 - 64
		n0 = _mm_mul_ps(sum0, _mm_set1_ps(16777216.0f));
		v0 = _mm_cvttps_epi32(n0);
		v0 = _mm_xor_si128(v0, out2);
		v1 = _mm_shuffle_epi32(v0, _MM_SHUFFLE(0, 1, 2, 3));
		v0 = _mm_xor_si128(v0, v1);
		v1 = _mm_shuffle_epi32(v0, _MM_SHUFFLE(0, 1, 0, 1));
		v0 = _mm_xor_si128(v0, v1);

		// vs is now between 0 and 1
		sum0 = _mm_div_ps(sum0, _mm_set1_ps(64.0f));
		uint32_t n = _mm_cvtsi128_si32(v0);
		idx0 = scratchpad_ptr(lpad, n, 0, mask);
		idx1 = scratchpad_ptr(lpad, n, 1, mask);
		idx2 = scratchpad_ptr(lpad, n, 2, mask);
		idx3 = scratchpad_ptr(lpad, n, 3, mask);
	}
}

template<bool SOFT_AES, cryptonight_algo ALGO>
void cryptonight_hash_gpu(const void* input, size_t len, void* output, cn_context& ctx0) {
	set_float_rounding_mode_nearest();

  constexpr uint32_t MASK = ALGO > 0 ? CRYPTONIGHT_GPU_MASK : CRYPTONIGHT_MASK;
  constexpr uint32_t ITER = ALGO == 0 ? CRYPTONIGHT_ITER : CRYPTONIGHT_GPU_ITER;

	keccak((const uint8_t *)input, static_cast<uint8_t>(len), ctx0.hash_state, 200);

	cn_explode_scratchpad_gpu(ctx0.hash_state, ctx0.long_state, CRYPTONIGHT_MEMORY);

	cn_gpu_inner_ssse3(ctx0.hash_state, ctx0.long_state);

	cn_implode_scratchpad<SOFT_AES, CRYPTONIGHT_MEMORY, ALGO>((__m128i*)ctx0.long_state, (__m128i*)ctx0.hash_state);

	keccakf((uint64_t*)ctx0.hash_state);

	memcpy(output, ctx0.hash_state, 32);
}

}

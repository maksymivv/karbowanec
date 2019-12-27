// Copyright (c) 2019, Ryo Currency Project
//
// Portions of this file are available under BSD-3 license. Please see ORIGINAL-LICENSE for details
// All rights reserved.
//
// Ryo changes to this code are in public domain. Please note, other licences may apply to the file.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2014-2017, SUMOKOIN
// Parts of this file are originally copyright (c) 2014-2017, The Monero Project
// Parts of this file are originally copyright (c) 2012-2013, The Cryptonote developers

#include "keccak.h"
#include "aux_hash.h"
#include "cn_slow_hash.hpp"
#include "saes_data.h"

struct aesdata
{
	uint64_t v64x0;
	uint64_t v64x1;

	inline void load(const cn_sptr mem)
	{
		v64x0 = mem.as_uqword(0);
		v64x1 = mem.as_uqword(1);
	}

	inline void xor_load(const cn_sptr mem)
	{
		v64x0 ^= mem.as_uqword(0);
		v64x1 ^= mem.as_uqword(1);
	}

	inline void write(cn_sptr mem)
	{
		mem.as_uqword(0) = v64x0;
		mem.as_uqword(1) = v64x1;
	}

	inline aesdata& operator=(const aesdata& rhs) noexcept
	{
		v64x0 = rhs.v64x0;
		v64x1 = rhs.v64x1;
		return *this;
	}

	inline aesdata& operator^=(const aesdata& rhs) noexcept
	{
		v64x0 ^= rhs.v64x0;
		v64x1 ^= rhs.v64x1;
		return *this;
	}

	inline aesdata& operator^=(uint32_t rhs) noexcept
	{
		uint64_t t = (uint64_t(rhs) << 32) | uint64_t(rhs);
		v64x0 ^= t;
		v64x1 ^= t;
		return *this;
	}

	inline void get_quad(uint32_t& x0, uint32_t& x1, uint32_t& x2, uint32_t& x3)
	{
		x0 = v64x0;
		x1 = v64x0 >> 32;
		x2 = v64x1;
		x3 = v64x1 >> 32;
	}

	inline void set_quad(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3)
	{
		v64x0 = uint64_t(x0) | uint64_t(x1) << 32;
		v64x1 = uint64_t(x2) | uint64_t(x3) << 32;
	}
};

inline uint32_t sub_word(uint32_t key)
{
	return (saes_sbox[key >> 24] << 24) | (saes_sbox[(key >> 16) & 0xff] << 16) |
		   (saes_sbox[(key >> 8) & 0xff] << 8) | saes_sbox[key & 0xff];
}

#if defined(__clang__) || defined(__arm__) || defined(__aarch64__)
inline uint32_t rotr(uint32_t value, uint32_t amount)
{
	return (value >> amount) | (value << ((32 - amount) & 31));
}
#else
inline uint32_t rotr(uint32_t value, uint32_t amount)
{
	return _rotr(value, amount);
}
#endif

// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
inline void sl_xor(aesdata& x)
{
	uint32_t x0, x1, x2, x3;
	x.get_quad(x0, x1, x2, x3);
	x1 ^= x0;
	x2 ^= x1;
	x3 ^= x2;
	x.set_quad(x0, x1, x2, x3);
}

template <uint8_t rcon>
inline void soft_aes_genkey_sub(aesdata& xout0, aesdata& xout2)
{
	sl_xor(xout0);
	xout0 ^= rotr(sub_word(xout2.v64x1 >> 32), 8) ^ rcon;
	sl_xor(xout2);
	xout2 ^= sub_word(xout0.v64x1 >> 32);
}

inline void aes_genkey(const cn_sptr memory, aesdata& k0, aesdata& k1, aesdata& k2, aesdata& k3, aesdata& k4, aesdata& k5, aesdata& k6, aesdata& k7, aesdata& k8, aesdata& k9)
{
	aesdata xout0, xout2;

	xout0.load(memory);
	xout2.load(memory.offset(16));
	k0 = xout0;
	k1 = xout2;

	soft_aes_genkey_sub<0x01>(xout0, xout2);
	k2 = xout0;
	k3 = xout2;

	soft_aes_genkey_sub<0x02>(xout0, xout2);
	k4 = xout0;
	k5 = xout2;

	soft_aes_genkey_sub<0x04>(xout0, xout2);
	k6 = xout0;
	k7 = xout2;

	soft_aes_genkey_sub<0x08>(xout0, xout2);
	k8 = xout0;
	k9 = xout2;
}

inline void aes_round(aesdata& val, const aesdata& key)
{
	uint32_t x0, x1, x2, x3;
	val.get_quad(x0, x1, x2, x3);
	val.set_quad(saes_table[0][x0 & 0xff] ^ saes_table[1][(x1 >> 8) & 0xff] ^ saes_table[2][(x2 >> 16) & 0xff] ^ saes_table[3][x3 >> 24],
				 saes_table[0][x1 & 0xff] ^ saes_table[1][(x2 >> 8) & 0xff] ^ saes_table[2][(x3 >> 16) & 0xff] ^ saes_table[3][x0 >> 24],
				 saes_table[0][x2 & 0xff] ^ saes_table[1][(x3 >> 8) & 0xff] ^ saes_table[2][(x0 >> 16) & 0xff] ^ saes_table[3][x1 >> 24],
				 saes_table[0][x3 & 0xff] ^ saes_table[1][(x0 >> 8) & 0xff] ^ saes_table[2][(x1 >> 16) & 0xff] ^ saes_table[3][x2 >> 24]);
	val ^= key;
}

inline void aes_round8(const aesdata& key, aesdata& x0, aesdata& x1, aesdata& x2, aesdata& x3, aesdata& x4, aesdata& x5, aesdata& x6, aesdata& x7)
{
	aes_round(x0, key);
	aes_round(x1, key);
	aes_round(x2, key);
	aes_round(x3, key);
	aes_round(x4, key);
	aes_round(x5, key);
	aes_round(x6, key);
	aes_round(x7, key);
}

inline void xor_shift(aesdata& x0, aesdata& x1, aesdata& x2, aesdata& x3, aesdata& x4, aesdata& x5, aesdata& x6, aesdata& x7)
{
	aesdata tmp = x0;
	x0 ^= x1;
	x1 ^= x2;
	x2 ^= x3;
	x3 ^= x4;
	x4 ^= x5;
	x5 ^= x6;
	x6 ^= x7;
	x7 ^= tmp;
}

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::implode_scratchpad_soft()
{
	aesdata x0, x1, x2, x3, x4, x5, x6, x7;
	aesdata k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey(spad.as_uqword() + 4, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

	x0.load(spad.as_uqword() + 8);
	x1.load(spad.as_uqword() + 10);
	x2.load(spad.as_uqword() + 12);
	x3.load(spad.as_uqword() + 14);
	x4.load(spad.as_uqword() + 16);
	x5.load(spad.as_uqword() + 18);
	x6.load(spad.as_uqword() + 20);
	x7.load(spad.as_uqword() + 22);

	for(size_t i = 0; i < MEMORY / sizeof(uint64_t); i += 16)
	{
		x0.xor_load(lpad.as_uqword() + i + 0);
		x1.xor_load(lpad.as_uqword() + i + 2);
		x2.xor_load(lpad.as_uqword() + i + 4);
		x3.xor_load(lpad.as_uqword() + i + 6);
		x4.xor_load(lpad.as_uqword() + i + 8);
		x5.xor_load(lpad.as_uqword() + i + 10);
		x6.xor_load(lpad.as_uqword() + i + 12);
		x7.xor_load(lpad.as_uqword() + i + 14);

		aes_round8(k0, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k1, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k2, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k3, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k4, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k5, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k6, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k7, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k8, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k9, x0, x1, x2, x3, x4, x5, x6, x7);

		if(POW_VER > 0)
			xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
	}

	// Note, this loop is only executed if POW_VER > 0
	for(size_t i = 0; POW_VER > 0 && i < MEMORY / sizeof(uint64_t); i += 16)
	{
		x0.xor_load(lpad.as_uqword() + i + 0);
		x1.xor_load(lpad.as_uqword() + i + 2);
		x2.xor_load(lpad.as_uqword() + i + 4);
		x3.xor_load(lpad.as_uqword() + i + 6);
		x4.xor_load(lpad.as_uqword() + i + 8);
		x5.xor_load(lpad.as_uqword() + i + 10);
		x6.xor_load(lpad.as_uqword() + i + 12);
		x7.xor_load(lpad.as_uqword() + i + 14);

		aes_round8(k0, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k1, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k2, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k3, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k4, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k5, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k6, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k7, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k8, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k9, x0, x1, x2, x3, x4, x5, x6, x7);

		xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
	}

	// Note, this loop is only executed if POW_VER > 0
	for(size_t i = 0; POW_VER > 0 && i < 16; i++)
	{
		aes_round8(k0, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k1, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k2, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k3, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k4, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k5, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k6, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k7, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k8, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k9, x0, x1, x2, x3, x4, x5, x6, x7);

		xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
	}

	x0.write(spad.as_uqword() + 8);
	x1.write(spad.as_uqword() + 10);
	x2.write(spad.as_uqword() + 12);
	x3.write(spad.as_uqword() + 14);
	x4.write(spad.as_uqword() + 16);
	x5.write(spad.as_uqword() + 18);
	x6.write(spad.as_uqword() + 20);
	x7.write(spad.as_uqword() + 22);
}

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::explode_scratchpad_soft()
{
	aesdata x0, x1, x2, x3, x4, x5, x6, x7;
	aesdata k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey(spad.as_uqword(), k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

	x0.load(spad.as_uqword() + 8);
	x1.load(spad.as_uqword() + 10);
	x2.load(spad.as_uqword() + 12);
	x3.load(spad.as_uqword() + 14);
	x4.load(spad.as_uqword() + 16);
	x5.load(spad.as_uqword() + 18);
	x6.load(spad.as_uqword() + 20);
	x7.load(spad.as_uqword() + 22);

	// Note, this loop is only executed if POW_VER > 0
	for(size_t i = 0; POW_VER > 0 && i < 16; i++)
	{
		aes_round8(k0, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k1, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k2, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k3, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k4, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k5, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k6, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k7, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k8, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k9, x0, x1, x2, x3, x4, x5, x6, x7);

		xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
	}

	for(size_t i = 0; i < MEMORY / sizeof(uint64_t); i += 16)
	{
		aes_round8(k0, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k1, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k2, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k3, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k4, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k5, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k6, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k7, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k8, x0, x1, x2, x3, x4, x5, x6, x7);
		aes_round8(k9, x0, x1, x2, x3, x4, x5, x6, x7);

		x0.write(lpad.as_uqword() + i + 0);
		x1.write(lpad.as_uqword() + i + 2);
		x2.write(lpad.as_uqword() + i + 4);
		x3.write(lpad.as_uqword() + i + 6);
		x4.write(lpad.as_uqword() + i + 8);
		x5.write(lpad.as_uqword() + i + 10);
		x6.write(lpad.as_uqword() + i + 12);
		x7.write(lpad.as_uqword() + i + 14);
	}
}

inline void generate_512(uint64_t idx, const uint64_t* in, uint8_t* out)
{
	constexpr size_t hash_size = 200; // 25x8 bytes
	alignas(16) uint64_t hash[25];

	memcpy(hash, in, hash_size);
	hash[0] ^= idx;

	keccakf(hash);
	memcpy(out, hash, 160);
	out += 160;

	keccakf(hash);
	memcpy(out, hash, 176);
	out += 176;

	keccakf(hash);
	memcpy(out, hash, 176);
}

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::explode_scratchpad_3()
{
	for(uint64_t i = 0; i < MEMORY / 512; i++)
	{
		generate_512(i, spad.as_uqword(), lpad.as_byte() + i * 512);
	}
}

#ifdef BUILD32
inline uint64_t _umul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi)
{
	// multiplier   = ab = a * 2^32 + b
	// multiplicand = cd = c * 2^32 + d
	// ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
	uint64_t a = multiplier >> 32;
	uint64_t b = multiplier & 0xFFFFFFFF;
	uint64_t c = multiplicand >> 32;
	uint64_t d = multiplicand & 0xFFFFFFFF;

	uint64_t ac = a * c;
	uint64_t ad = a * d;
	uint64_t bc = b * c;
	uint64_t bd = b * d;

	uint64_t adbc = ad + bc;
	uint64_t adbc_carry = adbc < ad ? 1 : 0;

	// multiplier * multiplicand = product_hi * 2^64 + product_lo
	uint64_t product_lo = bd + (adbc << 32);
	uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
	*product_hi = ac + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;

	return product_lo;
}
#else
#if !defined(HAS_WIN_INTRIN_API)
inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
	unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
	*hi = r >> 64;
	return (uint64_t)r;
}
#endif
#endif

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::software_hash(const void* in, size_t len, void* out)
{
	keccak((const uint8_t*)in, len, spad.as_byte(), 200);

	explode_scratchpad_soft();

	uint64_t* h0 = spad.as_uqword();

	aesdata ax;
	ax.v64x0 = h0[0] ^ h0[4];
	ax.v64x1 = h0[1] ^ h0[5];

	aesdata bx;
	bx.v64x0 = h0[2] ^ h0[6];
	bx.v64x1 = h0[3] ^ h0[7];

	aesdata cx;
	cn_sptr idx = scratchpad_ptr(ax.v64x0);

	for(size_t i = 0; i < ITER / 2; i++)
	{
		uint64_t hi, lo;
		cx.load(idx);

		aes_round(cx, ax);

		if(POW_VER == 3)
		{
			__m128i bx_xmm = _mm_set_epi64x(bx.v64x1, bx.v64x0);
			while((cx.v64x0 & 0xf) != 0)
			{
				__m128i cx_xmm = _mm_set_epi64x(cx.v64x1, cx.v64x0);
				cx_xmm = _mm_xor_si128(cx_xmm, bx_xmm);
#if defined(__arm__) || defined(__aarch64__)
        __m128 da = _mm_cvtepi32_ps(cx_xmm);
        __m128 db = _mm_cvtepi32_ps(_mm_shuffle_epi32_default(cx_xmm, _MM_SHUFFLE(0, 1, 2, 3)));
        da = _mm_mul_ps(da, db);
        __m128i dx = _mm_castps_si128(da);
#else
				__m128d da = _mm_cvtepi32_pd(cx_xmm);
				__m128d db = _mm_cvtepi32_pd(_mm_shuffle_epi32(cx_xmm, _MM_SHUFFLE(0,1,2,3)));
				da = _mm_mul_pd(da, db);
				__m128i dx = _mm_castpd_si128(da);
#endif
				cx.v64x0 = _mm_cvtsi128_si64(dx);
				dx = _mm_shuffle_epi32(dx, _MM_SHUFFLE(1,0,3,2));
				cx.v64x1 = _mm_cvtsi128_si64(dx);
				aes_round(cx, ax);
			}
			aes_round(cx, ax);
		}

		bx ^= cx;
		bx.write(idx);
		idx = scratchpad_ptr(cx.v64x0);
		bx.load(idx);

		lo = _umul128(cx.v64x0, bx.v64x0, &hi);

		ax.v64x0 += hi;
		ax.v64x1 += lo;
		ax.write(idx);

		ax ^= bx;
		idx = scratchpad_ptr(ax.v64x0);
		if(POW_VER > 0 && POW_VER < 3)
		{
			int64_t n = idx.as_qword(0);
			int32_t d = idx.as_dword(2);

#if defined(__arm__)
			asm volatile("nop"); //Fix for RasPi3 ARM - maybe needed on armv8
#endif

			int64_t q = n / (d | 5);
			idx.as_qword(0) = n ^ q;
			idx = scratchpad_ptr(d ^ q);
		}

		bx.load(idx);

		aes_round(bx, ax);

		if(POW_VER == 3)
		{
			__m128i cx_xmm = _mm_set_epi64x(cx.v64x1, cx.v64x0);
			while((bx.v64x0 & 0xf) != 0)
			{
				__m128i bx_xmm = _mm_set_epi64x(bx.v64x1, bx.v64x0);
				bx_xmm = _mm_xor_si128(bx_xmm, cx_xmm);
#if defined(__arm__) || defined(__aarch64__)
        __m128 da = _mm_cvtepi32_ps(bx_xmm);
        __m128 db = _mm_cvtepi32_ps(_mm_shuffle_epi32(bx_xmm, _MM_SHUFFLE(0, 1, 2, 3)));
        da = _mm_mul_ps(da, db);
        __m128i dx = _mm_castps_si128(da);
#else
        __m128d da = _mm_cvtepi32_pd(bx_xmm);
        __m128d db = _mm_cvtepi32_pd(_mm_shuffle_epi32(bx_xmm, _MM_SHUFFLE(0, 1, 2, 3)));
        da = _mm_mul_pd(da, db);
        __m128i dx = _mm_castpd_si128(da);
#endif
				bx.v64x0 = _mm_cvtsi128_si64(dx);
				dx = _mm_shuffle_epi32(dx, _MM_SHUFFLE(1,0,3,2));
				bx.v64x1 = _mm_cvtsi128_si64(dx);
				aes_round(bx, ax);
			}
			aes_round(bx, ax);
		}

		cx ^= bx;
		cx.write(idx);
		idx = scratchpad_ptr(bx.v64x0);
		cx.load(idx);

		lo = _umul128(bx.v64x0, cx.v64x0, &hi);

		ax.v64x0 += hi;
		ax.v64x1 += lo;
		ax.write(idx);
		ax ^= cx;
		idx = scratchpad_ptr(ax.v64x0);
		if(POW_VER > 0 && POW_VER < 3)
		{
			int64_t n = idx.as_qword(0); // read bytes 0 - 7
			int32_t d = idx.as_dword(2); // read bytes 8 - 11

#if defined(__arm__) || defined(__aarch64__)
			asm volatile("nop"); //Fix for RasPi3 ARM - maybe needed on armv8
#endif

			int64_t q = n / (d | 5);
			idx.as_qword(0) = n ^ q;
			idx = scratchpad_ptr(d ^ q);
		}
	}

	implode_scratchpad_soft();

	keccakf(spad.as_uqword());

	switch(spad.as_byte(0) & 3)
	{
	case 0:
		blake256_hash(spad.as_byte(), (uint8_t*)out);
		break;
	case 1:
		groestl_hash(spad.as_byte(), (uint8_t*)out);
		break;
	case 2:
		jh_hash(spad.as_byte(), (uint8_t*)out);
		break;
	case 3:
		skein_hash(spad.as_byte(), (uint8_t*)out);
		break;
	}
}

template class cn_v1_hash_t;
template class cn_v2_hash_t;
template class cn_v3_hash_t;
template class cn_v4_hash_t;

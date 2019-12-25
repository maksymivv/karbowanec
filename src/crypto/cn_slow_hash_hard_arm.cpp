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

#define CN_ADD_TARGETS_AND_HEADERS

#include "keccak.h"
#include "aux_hash.h"
#include "cn_slow_hash.hpp"

#ifdef HAS_ARM_HW
//extern const uint8_t saes_sbox[256];



/*
AES Tables Implementation is
---------------------------------------------------------------------------
Copyright (c) 1998-2013, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
*/

#define saes_data(w)                                                                \
	{                                                                               \
		w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),     \
			w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76), \
			w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0), \
			w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0), \
			w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc), \
			w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15), \
			w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a), \
			w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75), \
			w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0), \
			w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84), \
			w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b), \
			w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf), \
			w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85), \
			w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8), \
			w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5), \
			w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2), \
			w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17), \
			w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73), \
			w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88), \
			w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb), \
			w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c), \
			w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79), \
			w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9), \
			w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08), \
			w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6), \
			w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a), \
			w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e), \
			w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e), \
			w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94), \
			w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf), \
			w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68), \
			w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16)  \
	}

#define SAES_WPOLY 0x011b

#define saes_b2w(b0, b1, b2, b3) (((uint32_t)(b3) << 24) | \
								  ((uint32_t)(b2) << 16) | ((uint32_t)(b1) << 8) | (b0))

#define saes_f2(x) ((x << 1) ^ (((x >> 7) & 1) * SAES_WPOLY))
#define saes_f3(x) (saes_f2(x) ^ x)
#define saes_h0(x) (x)

#define saes_u0(p) saes_b2w(saes_f2(p), p, p, saes_f3(p))
#define saes_u1(p) saes_b2w(saes_f3(p), saes_f2(p), p, p)
#define saes_u2(p) saes_b2w(p, saes_f3(p), saes_f2(p), p)
#define saes_u3(p) saes_b2w(p, p, saes_f3(p), saes_f2(p))

alignas(16) const uint32_t saes_table[4][256] = { saes_data(saes_u0), saes_data(saes_u1), saes_data(saes_u2), saes_data(saes_u3) };
alignas(16) extern const uint8_t saes_sbox[256] = saes_data(saes_h0);

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

  for (size_t i = 0; i < MEMORY / sizeof(uint64_t); i += 16)
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

    if (POW_VER > 0)
      xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
  }

  // Note, this loop is only executed if POW_VER > 0
  for (size_t i = 0; POW_VER > 0 && i < MEMORY / sizeof(uint64_t); i += 16)
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
  for (size_t i = 0; POW_VER > 0 && i < 16; i++)
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
  for (size_t i = 0; POW_VER > 0 && i < 16; i++)
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

  for (size_t i = 0; i < MEMORY / sizeof(uint64_t); i += 16)
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
  for (uint64_t i = 0; i < MEMORY / 512; i++)
  {
    generate_512(i, spad.as_uqword(), lpad.as_byte() + i * 512);
  }
}




struct aeskeydata
{
	uint32_t x0;
	uint32_t x1;
	uint32_t x2;
	uint32_t x3;

	aeskeydata(const uint8_t* memory)
	{
		const uint32_t* mem = reinterpret_cast<const uint32_t*>(memory);
		x0 = mem[0];
		x1 = mem[1];
		x2 = mem[2];
		x3 = mem[3];
	}

	inline uint8x16_t store()
	{
		uint32x4_t tmp = {x0, x1, x2, x3};
		return vreinterpretq_u8_u32(tmp);
	}

	inline aeskeydata& operator^=(uint32_t rhs) noexcept
	{
		x0 ^= rhs;
		x1 ^= rhs;
		x2 ^= rhs;
		x3 ^= rhs;
		return *this;
	}
};

// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
inline void sl_xor(aeskeydata& x)
{
	x.x1 ^= x.x0;
	x.x2 ^= x.x1;
	x.x3 ^= x.x2;
}

inline uint32_t rotr(uint32_t value, uint32_t amount)
{
	return (value >> amount) | (value << ((32 - amount) & 31));
}

template <uint8_t rcon>
inline void soft_aes_genkey_sub(aeskeydata& xout0, aeskeydata& xout2)
{
	uint32_t tmp;
	sl_xor(xout0);
	xout0 ^= rotr(sub_word(xout2.x3), 8) ^ rcon;
	sl_xor(xout2);
	xout2 ^= sub_word(xout0.x3);
}

inline void aes_genkey(const uint8_t* memory, uint8x16_t& k0, uint8x16_t& k1, uint8x16_t& k2, uint8x16_t& k3, uint8x16_t& k4,
					   uint8x16_t& k5, uint8x16_t& k6, uint8x16_t& k7, uint8x16_t& k8, uint8x16_t& k9)
{
	aeskeydata xout0(memory);
	aeskeydata xout2(memory + 16);

	k0 = xout0.store();
	k1 = xout2.store();

	soft_aes_genkey_sub<0x01>(xout0, xout2);
	k2 = xout0.store();
	k3 = xout2.store();

	soft_aes_genkey_sub<0x02>(xout0, xout2);
	k4 = xout0.store();
	k5 = xout2.store();

	soft_aes_genkey_sub<0x04>(xout0, xout2);
	k6 = xout0.store();
	k7 = xout2.store();

	soft_aes_genkey_sub<0x08>(xout0, xout2);
	k8 = xout0.store();
	k9 = xout2.store();
}

inline void aes_round10(uint8x16_t& x, const uint8x16_t& k0, const uint8x16_t& k1, const uint8x16_t& k2, const uint8x16_t& k3,
						const uint8x16_t& k4, const uint8x16_t& k5, const uint8x16_t& k6, const uint8x16_t& k7, const uint8x16_t& k8, const uint8x16_t& k9)
{
	x = vaesmcq_u8(vaeseq_u8(x, vdupq_n_u8(0)));
	x = vaesmcq_u8(vaeseq_u8(x, k0));
	x = vaesmcq_u8(vaeseq_u8(x, k1));
	x = vaesmcq_u8(vaeseq_u8(x, k2));
	x = vaesmcq_u8(vaeseq_u8(x, k3));
	x = vaesmcq_u8(vaeseq_u8(x, k4));
	x = vaesmcq_u8(vaeseq_u8(x, k5));
	x = vaesmcq_u8(vaeseq_u8(x, k6));
	x = vaesmcq_u8(vaeseq_u8(x, k7));
	x = vaesmcq_u8(vaeseq_u8(x, k8));
	x = veorq_u8(x, k9);
}

inline void xor_shift(uint8x16_t& x0, uint8x16_t& x1, uint8x16_t& x2, uint8x16_t& x3, uint8x16_t& x4, uint8x16_t& x5, uint8x16_t& x6, uint8x16_t& x7)
{
	uint8x16_t tmp0 = x0;
	x0 ^= x1;
	x1 ^= x2;
	x2 ^= x3;
	x3 ^= x4;
	x4 ^= x5;
	x5 ^= x6;
	x6 ^= x7;
	x7 ^= tmp0;
}

inline void mem_load(cn_sptr& lpad, size_t i, uint8x16_t& x0, uint8x16_t& x1, uint8x16_t& x2, uint8x16_t& x3, uint8x16_t& x4, uint8x16_t& x5, uint8x16_t& x6, uint8x16_t& x7)
{
	x0 ^= vld1q_u8(lpad.as_byte() + i);
	x1 ^= vld1q_u8(lpad.as_byte() + i + 16);
	x2 ^= vld1q_u8(lpad.as_byte() + i + 32);
	x3 ^= vld1q_u8(lpad.as_byte() + i + 48);
	x4 ^= vld1q_u8(lpad.as_byte() + i + 64);
	x5 ^= vld1q_u8(lpad.as_byte() + i + 80);
	x6 ^= vld1q_u8(lpad.as_byte() + i + 96);
	x7 ^= vld1q_u8(lpad.as_byte() + i + 112);
}

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::implode_scratchpad_hard()
{
	uint8x16_t x0, x1, x2, x3, x4, x5, x6, x7;
	uint8x16_t k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey(spad.as_byte() + 32, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

	x0 = vld1q_u8(spad.as_byte() + 64);
	x1 = vld1q_u8(spad.as_byte() + 80);
	x2 = vld1q_u8(spad.as_byte() + 96);
	x3 = vld1q_u8(spad.as_byte() + 112);
	x4 = vld1q_u8(spad.as_byte() + 128);
	x5 = vld1q_u8(spad.as_byte() + 144);
	x6 = vld1q_u8(spad.as_byte() + 160);
	x7 = vld1q_u8(spad.as_byte() + 176);

	for(size_t i = 0; i < MEMORY; i += 128)
	{
		mem_load(lpad, i, x0, x1, x2, x3, x4, x5, x6, x7);

		aes_round10(x0, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x1, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x2, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x3, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x4, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x5, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x6, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x7, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

		if(POW_VER > 0)
			xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
	}

	for(size_t i = 0; POW_VER > 0 && i < MEMORY; i += 128)
	{
		mem_load(lpad, i, x0, x1, x2, x3, x4, x5, x6, x7);

		aes_round10(x0, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x1, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x2, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x3, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x4, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x5, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x6, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x7, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

		xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
	}

	for(size_t i = 0; POW_VER > 0 && i < 16; i++)
	{
		aes_round10(x0, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x1, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x2, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x3, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x4, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x5, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x6, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x7, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

		xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
	}

	vst1q_u8(spad.as_byte() + 64, x0);
	vst1q_u8(spad.as_byte() + 80, x1);
	vst1q_u8(spad.as_byte() + 96, x2);
	vst1q_u8(spad.as_byte() + 112, x3);
	vst1q_u8(spad.as_byte() + 128, x4);
	vst1q_u8(spad.as_byte() + 144, x5);
	vst1q_u8(spad.as_byte() + 160, x6);
	vst1q_u8(spad.as_byte() + 176, x7);
}

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::explode_scratchpad_hard()
{
	uint8x16_t x0, x1, x2, x3, x4, x5, x6, x7;
	uint8x16_t k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey(spad.as_byte(), k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

	x0 = vld1q_u8(spad.as_byte() + 64);
	x1 = vld1q_u8(spad.as_byte() + 80);
	x2 = vld1q_u8(spad.as_byte() + 96);
	x3 = vld1q_u8(spad.as_byte() + 112);
	x4 = vld1q_u8(spad.as_byte() + 128);
	x5 = vld1q_u8(spad.as_byte() + 144);
	x6 = vld1q_u8(spad.as_byte() + 160);
	x7 = vld1q_u8(spad.as_byte() + 176);

	for(size_t i = 0; POW_VER > 0 && i < 16; i++)
	{
		aes_round10(x0, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x1, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x2, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x3, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x4, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x5, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x6, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x7, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

		xor_shift(x0, x1, x2, x3, x4, x5, x6, x7);
	}

	for(size_t i = 0; i < MEMORY; i += 128)
	{
		aes_round10(x0, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x1, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x2, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x3, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x4, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x5, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x6, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);
		aes_round10(x7, k0, k1, k2, k3, k4, k5, k6, k7, k8, k9);

		vst1q_u8(lpad.as_byte() + i, x0);
		vst1q_u8(lpad.as_byte() + i + 16, x1);
		vst1q_u8(lpad.as_byte() + i + 32, x2);
		vst1q_u8(lpad.as_byte() + i + 48, x3);
		vst1q_u8(lpad.as_byte() + i + 64, x4);
		vst1q_u8(lpad.as_byte() + i + 80, x5);
		vst1q_u8(lpad.as_byte() + i + 96, x6);
		vst1q_u8(lpad.as_byte() + i + 112, x7);
	}
}

inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
	unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
	*hi = r >> 64;
	return (uint64_t)r;
}

inline uint8x16_t _mm_set_epi64x(const uint64_t a, const uint64_t b)
{
	return vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(b), vcreate_u64(a)));
}

#define vreinterpretq_s32_m128i(x) \
	(x)

#define vreinterpretq_m128i_s32(x) \
	(x)

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::hardware_hash(const void* in, size_t len, void* out)
{
	keccak((const uint8_t*)in, len, spad.as_byte(), 200);

	explode_scratchpad_hard();

	uint64_t* h0 = spad.as_uqword();

	uint64_t al0 = h0[0] ^ h0[4];
	uint64_t ah0 = h0[1] ^ h0[5];
	uint8x16_t bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

	uint64_t idx0 = h0[0] ^ h0[4];

	const uint8x16_t zero = vdupq_n_u8(0);
	// Optim - 90% time boundary
	for(size_t i = 0; i < ITER; i++)
	{
		uint8x16_t cx;
		cx = vld1q_u8(scratchpad_ptr(idx0).as_byte());
		uint8x16_t ax0 = _mm_set_epi64x(ah0, al0);
		cx = vaesmcq_u8(vaeseq_u8(cx, zero)) ^ ax0;
		if (POW_VER == 3)
		{
			int32x4_t _cx = vreinterpretq_s32_u8(cx);
			while ((vheor_s32(_cx) & 0xf) != 0)
			{
				cx = cx ^ bx0;
				float64x2_t da = vcvtq_f64_s64(vreinterpretq_s64_u8(cx));
				float64x2_t db = vcvtq_f64_s64(vreinterpretq_s64_s16(_mm_shuffle_epi32_default(vreinterpretq_s16_u8(cx), _MM_SHUFFLE(0, 1, 2, 3))));
				da = vmulq_f64(da, db);
				cx = vaesmcq_u8(vaeseq_u8(vreinterpretq_u8_f64(da), zero)) ^ ax0;
			}
			cx = vaesmcq_u8(vaeseq_u8(cx, zero)) ^ ax0;
		}

		vst1q_u8(scratchpad_ptr(idx0).as_byte(), bx0 ^ cx);

		idx0 = vgetq_lane_u64(vreinterpretq_u64_u8(cx), 0);
		bx0 = cx;

		uint64_t hi, lo, cl, ch;
		cl = scratchpad_ptr(idx0).as_uqword(0);
		ch = scratchpad_ptr(idx0).as_uqword(1);

		lo = _umul128(idx0, cl, &hi);

		al0 += hi;
		ah0 += lo;
		scratchpad_ptr(idx0).as_uqword(0) = al0;
		scratchpad_ptr(idx0).as_uqword(1) = ah0;
		ah0 ^= ch;
		al0 ^= cl;
		idx0 = al0;

		if(POW_VER > 0 && POW_VER < 3)
		{
			int64_t n = scratchpad_ptr(idx0).as_qword(0);
			int32_t d = scratchpad_ptr(idx0).as_dword(2);
#if defined(__arm__) || defined(__aarch64__)
			asm volatile("nop"); //Fix for RasPi3 ARM - maybe needed on armv8
#endif
			int64_t q = n / (d | 5);
			scratchpad_ptr(idx0).as_qword(0) = n ^ q;
			idx0 = d ^ q;
		}
	}

	implode_scratchpad_hard();

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

#endif // HAS_ARM_HW

#ifdef HAS_ARM

inline void prep_dv(cn_sptr& idx, int32x4_t& v, float32x4_t& n)
{
	v = vld1q_s32((int32_t*)idx.as_void());
	n = vcvtq_f32_s32(v);
}

// 14
inline void sub_round(const float32x4_t& n0, const float32x4_t& n1, const float32x4_t& n2, const float32x4_t& n3,
					  const float32x4_t& rnd_c, float32x4_t& n, float32x4_t& d, float32x4_t& c)
{
	float32x4_t ln1 = vaddq_f32(n1, c);
	float32x4_t nn = vmulq_f32(n0, c);
	nn = vmulq_f32(ln1, vmulq_f32(nn, nn));
	vandq_f32(nn, 0xFEFFFFFF);
	vorq_f32(nn, 0x00800000);
	n = vaddq_f32(n, nn);

	float32x4_t ln3 = vsubq_f32(n3, c);
	float32x4_t dd = vmulq_f32(n2, c);
	dd = vmulq_f32(ln3, vmulq_f32(dd, dd));
	vandq_f32(dd, 0xFEFFFFFF);
	vorq_f32(dd, 0x00800000);
	d = vaddq_f32(d, dd);

	//Constant feedback
	c = vaddq_f32(c, rnd_c);
	c = vaddq_f32(c, vdupq_n_f32(0.734375f));
	float32x4_t r = vaddq_f32(nn, dd);
	vandq_f32(r, 0x807FFFFF);
	vorq_f32(r, 0x40000000);
	c = vaddq_f32(c, r);
}

inline void round_compute(const float32x4_t& n0, const float32x4_t& n1, const float32x4_t& n2, const float32x4_t& n3,
						  const float32x4_t& rnd_c, float32x4_t& c, float32x4_t& r)
{
	float32x4_t n = vdupq_n_f32(0.0f), d = vdupq_n_f32(0.0f);

	sub_round(n0, n1, n2, n3, rnd_c, n, d, c);
	sub_round(n1, n2, n3, n0, rnd_c, n, d, c);
	sub_round(n2, n3, n0, n1, rnd_c, n, d, c);
	sub_round(n3, n0, n1, n2, rnd_c, n, d, c);
	sub_round(n3, n2, n1, n0, rnd_c, n, d, c);
	sub_round(n2, n1, n0, n3, rnd_c, n, d, c);
	sub_round(n1, n0, n3, n2, rnd_c, n, d, c);
	sub_round(n0, n3, n2, n1, rnd_c, n, d, c);

	// Make sure abs(d) > 2.0 - this prevents division by zero and accidental overflows by division by < 1.0
	vandq_f32(d, 0xFF7FFFFF);
	vorq_f32(d, 0x40000000);
	r = vaddq_f32(r, vdivq_f32(n, d));
}

template <bool add>
inline int32x4_t single_comupte(const float32x4_t& n0, const float32x4_t& n1, const float32x4_t& n2, const float32x4_t& n3,
								float cnt, const float32x4_t& rnd_c, float32x4_t& sum)
{
	float32x4_t c = vdupq_n_f32(cnt);
	float32x4_t r = vdupq_n_f32(0.0f);

	round_compute(n0, n1, n2, n3, rnd_c, c, r);
	round_compute(n0, n1, n2, n3, rnd_c, c, r);
	round_compute(n0, n1, n2, n3, rnd_c, c, r);
	round_compute(n0, n1, n2, n3, rnd_c, c, r);

	// do a quick fmod by setting exp to 2
	vandq_f32(r, 0x807FFFFF);
	vorq_f32(r, 0x40000000);

	if(add)
		sum = vaddq_f32(sum, r);
	else
		sum = r;

	const float32x4_t cc2 = vdupq_n_f32(536870880.0f);
	r = vmulq_f32(r, cc2); // 35
	return vcvtq_s32_f32(r);
}

template <size_t rot>
inline void single_comupte_wrap(const float32x4_t& n0, const float32x4_t& n1, const float32x4_t& n2, const float32x4_t& n3,
								float cnt, const float32x4_t& rnd_c, float32x4_t& sum, int32x4_t& out)
{
	int32x4_t r = single_comupte<rot % 2 != 0>(n0, n1, n2, n3, cnt, rnd_c, sum);
	vrot_si32<rot>(r);
	out = veorq_s32(out, r);
}

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::inner_hash_3()
{
	uint32_t s = spad.as_dword(0) >> 8;
	cn_sptr idx0 = scratchpad_ptr(s, 0);
	cn_sptr idx1 = scratchpad_ptr(s, 1);
	cn_sptr idx2 = scratchpad_ptr(s, 2);
	cn_sptr idx3 = scratchpad_ptr(s, 3);
	float32x4_t sum0 = vdupq_n_f32(0.0f);

	for(size_t i = 0; i < ITER; i++)
	{
		float32x4_t n0, n1, n2, n3;
		int32x4_t v0, v1, v2, v3;
		float32x4_t suma, sumb, sum1, sum2, sum3;

		prep_dv(idx0, v0, n0);
		prep_dv(idx1, v1, n1);
		prep_dv(idx2, v2, n2);
		prep_dv(idx3, v3, n3);
		float32x4_t rc = sum0;

		int32x4_t out, out2;
		out = vdupq_n_s32(0);
		single_comupte_wrap<0>(n0, n1, n2, n3, 1.3437500f, rc, suma, out);
		single_comupte_wrap<1>(n0, n2, n3, n1, 1.2812500f, rc, suma, out);
		single_comupte_wrap<2>(n0, n3, n1, n2, 1.3593750f, rc, sumb, out);
		single_comupte_wrap<3>(n0, n3, n2, n1, 1.3671875f, rc, sumb, out);
		sum0 = vaddq_f32(suma, sumb);
		vst1q_s32((int32_t*)idx0.as_void(), veorq_s32(v0, out));
		out2 = out;

		out = vdupq_n_s32(0);
		single_comupte_wrap<0>(n1, n0, n2, n3, 1.4296875f, rc, suma, out);
		single_comupte_wrap<1>(n1, n2, n3, n0, 1.3984375f, rc, suma, out);
		single_comupte_wrap<2>(n1, n3, n0, n2, 1.3828125f, rc, sumb, out);
		single_comupte_wrap<3>(n1, n3, n2, n0, 1.3046875f, rc, sumb, out);
		sum1 = vaddq_f32(suma, sumb);
		vst1q_s32((int32_t*)idx1.as_void(), veorq_s32(v1, out));
		out2 = veorq_s32(out2, out);

		out = vdupq_n_s32(0);
		single_comupte_wrap<0>(n2, n1, n0, n3, 1.4140625f, rc, suma, out);
		single_comupte_wrap<1>(n2, n0, n3, n1, 1.2734375f, rc, suma, out);
		single_comupte_wrap<2>(n2, n3, n1, n0, 1.2578125f, rc, sumb, out);
		single_comupte_wrap<3>(n2, n3, n0, n1, 1.2890625f, rc, sumb, out);
		sum2 = vaddq_f32(suma, sumb);
		vst1q_s32((int32_t*)idx2.as_void(), veorq_s32(v2, out));
		out2 = veorq_s32(out2, out);

		out = vdupq_n_s32(0);
		single_comupte_wrap<0>(n3, n1, n2, n0, 1.3203125f, rc, suma, out);
		single_comupte_wrap<1>(n3, n2, n0, n1, 1.3515625f, rc, suma, out);
		single_comupte_wrap<2>(n3, n0, n1, n2, 1.3359375f, rc, sumb, out);
		single_comupte_wrap<3>(n3, n0, n2, n1, 1.4609375f, rc, sumb, out);
		sum3 = vaddq_f32(suma, sumb);
		vst1q_s32((int32_t*)idx3.as_void(), veorq_s32(v3, out));
		out2 = veorq_s32(out2, out);
		sum0 = vaddq_f32(sum0, sum1);
		sum2 = vaddq_f32(sum2, sum3);
		sum0 = vaddq_f32(sum0, sum2);

		const float32x4_t cc1 = vdupq_n_f32(16777216.0f);
		const float32x4_t cc2 = vdupq_n_f32(64.0f);
		vandq_f32(sum0, 0x7fffffff); // take abs(va) by masking the float sign bit
		// vs range 0 - 64
		n0 = vmulq_f32(sum0, cc1);
		v0 = vcvtq_s32_f32(n0);
		v0 = veorq_s32(v0, out2);
		uint32_t n = vheor_s32(v0);

		// vs is now between 0 and 1
		sum0 = vdivq_f32(sum0, cc2);
		idx0 = scratchpad_ptr(n, 0);
		idx1 = scratchpad_ptr(n, 1);
		idx2 = scratchpad_ptr(n, 2);
		idx3 = scratchpad_ptr(n, 3);
	}
}

#if defined(__aarch64__)
template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::hardware_hash_3(const void* in, size_t len, void* pout)
{
	keccak((const uint8_t*)in, len, spad.as_byte(), 200);

	explode_scratchpad_3();
	inner_hash_3();
	implode_scratchpad_hard();

	keccakf(spad.as_uqword());
	memcpy(pout, spad.as_byte(), 32);
}
#endif

template <size_t MEMORY, size_t ITER, size_t POW_VER>
void cn_slow_hash<MEMORY, ITER, POW_VER>::software_hash_3(const void* in, size_t len, void* pout)
{
	keccak((const uint8_t*)in, len, spad.as_byte(), 200);

	explode_scratchpad_3();
	inner_hash_3();
	implode_scratchpad_soft();

	keccakf(spad.as_uqword());
	memcpy(pout, spad.as_byte(), 32);
}

template class cn_v1_hash_t;
template class cn_v2_hash_t;
template class cn_v3_hash_t;
template class cn_v4_hash_t;
#endif

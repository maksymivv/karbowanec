// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2017, The Monero Project
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

#include <cstddef>
#include <limits>
#include <mutex>
#include <type_traits>
#include <vector>

#include <CryptoTypes.h>

#include "generic-ops.h"
#include "crypto-ops.h"
#include "crypto-util.h"
#include "hash.h"
#include "random.h"

namespace Crypto {

  class Error : public std::logic_error {
  public:
    explicit Error(const std::string &msg) : std::logic_error(msg) {}
  };

  class crypto_ops {
    crypto_ops();
    crypto_ops(const crypto_ops &);
    void operator=(const crypto_ops &);
    ~crypto_ops();

    static void generate_keys(PublicKey &, SecretKey &);
    friend void generate_keys(PublicKey &, SecretKey &);
    static void generate_deterministic_keys(PublicKey &pub, SecretKey &sec, SecretKey& second);
    friend void generate_deterministic_keys(PublicKey &pub, SecretKey &sec, SecretKey& second);
    static SecretKey generate_m_keys(PublicKey &pub, SecretKey &sec, const SecretKey& recovery_key = SecretKey(), bool recover = false);
    friend SecretKey generate_m_keys(PublicKey &pub, SecretKey &sec, const SecretKey& recovery_key, bool recover);
    static bool check_key(const PublicKey &);
    friend bool check_key(const PublicKey &);
    static bool secret_key_to_public_key(const SecretKey &, PublicKey &);
    friend bool secret_key_to_public_key(const SecretKey &, PublicKey &);
    static bool generate_key_derivation(const PublicKey &, const SecretKey &, KeyDerivation &);
    friend bool generate_key_derivation(const PublicKey &, const SecretKey &, KeyDerivation &);
    static bool derive_public_key(const KeyDerivation &, size_t, const PublicKey &, PublicKey &);
    friend bool derive_public_key(const KeyDerivation &, size_t, const PublicKey &, PublicKey &);
    friend bool derive_public_key(const KeyDerivation &, size_t, const PublicKey &, const uint8_t*, size_t, PublicKey &);
    static bool derive_public_key(const KeyDerivation &, size_t, const PublicKey &, const uint8_t*, size_t, PublicKey &);
    //hack for pg
    static bool underive_public_key_and_get_scalar(const KeyDerivation &, std::size_t, const PublicKey &, PublicKey &, EllipticCurveScalar &);
    friend bool underive_public_key_and_get_scalar(const KeyDerivation &, std::size_t, const PublicKey &, PublicKey &, EllipticCurveScalar &);
    static void generate_incomplete_key_image(const PublicKey &, EllipticCurvePoint &);
    friend void generate_incomplete_key_image(const PublicKey &, EllipticCurvePoint &);
    //
    static void derive_secret_key(const KeyDerivation &, size_t, const SecretKey &, SecretKey &);
    friend void derive_secret_key(const KeyDerivation &, size_t, const SecretKey &, SecretKey &);
    static void derive_secret_key(const KeyDerivation &, size_t, const SecretKey &, const uint8_t*, size_t, SecretKey &);
    friend void derive_secret_key(const KeyDerivation &, size_t, const SecretKey &, const uint8_t*, size_t, SecretKey &);
    static bool underive_public_key(const KeyDerivation &, size_t, const PublicKey &, PublicKey &);
    friend bool underive_public_key(const KeyDerivation &, size_t, const PublicKey &, PublicKey &);
    static bool underive_public_key(const KeyDerivation &, size_t, const PublicKey &, const uint8_t*, size_t, PublicKey &);
    friend bool underive_public_key(const KeyDerivation &, size_t, const PublicKey &, const uint8_t*, size_t, PublicKey &);
    static void generate_signature(const Hash &, const PublicKey &, const SecretKey &, Signature &);
    friend void generate_signature(const Hash &, const PublicKey &, const SecretKey &, Signature &);
    static bool check_signature(const Hash &, const PublicKey &, const Signature &);
    friend bool check_signature(const Hash &, const PublicKey &, const Signature &);
    static void generate_tx_proof(const Hash &, const PublicKey &, const PublicKey &, const PublicKey &, const SecretKey &, Signature &);
    friend void generate_tx_proof(const Hash &, const PublicKey &, const PublicKey &, const PublicKey &, const SecretKey &, Signature &);
    static bool check_tx_proof(const Hash &, const PublicKey &, const PublicKey &, const PublicKey &, const Signature &);
    friend bool check_tx_proof(const Hash &, const PublicKey &, const PublicKey &, const PublicKey &, const Signature &);
    static void generate_key_image(const PublicKey &, const SecretKey &, KeyImage &);
    friend void generate_key_image(const PublicKey &, const SecretKey &, KeyImage &);
    static KeyImage scalarmultKey(const KeyImage & P, const KeyImage & a);
    friend KeyImage scalarmultKey(const KeyImage & P, const KeyImage & a);
    static void hash_data_to_ec(const uint8_t*, std::size_t, PublicKey&);
    friend void hash_data_to_ec(const uint8_t*, std::size_t, PublicKey&);
    static void generate_ring_signature(const Hash &, const KeyImage &,
      const PublicKey *const *, size_t, const SecretKey &, size_t, Signature *);
    friend void generate_ring_signature(const Hash &, const KeyImage &,
      const PublicKey *const *, size_t, const SecretKey &, size_t, Signature *);
    static bool check_ring_signature(const Hash &, const KeyImage &,
      const PublicKey *const *, size_t, const Signature *);
    friend bool check_ring_signature(const Hash &, const KeyImage &,
      const PublicKey *const *, size_t, const Signature *);
  };

  /* Generate a new key pair
   */
  inline void generate_keys(PublicKey &pub, SecretKey &sec) {
    crypto_ops::generate_keys(pub, sec);
  }

  inline void generate_deterministic_keys(PublicKey &pub, SecretKey &sec, SecretKey& second) {
    crypto_ops::generate_deterministic_keys(pub, sec, second);
  }

  inline SecretKey generate_m_keys(PublicKey &pub, SecretKey &sec, const SecretKey& recovery_key = SecretKey(), bool recover = false) {
    return crypto_ops::generate_m_keys(pub, sec, recovery_key, recover);
  }

  /* Check a public key. Returns true if it is valid, false otherwise.
   */
  inline bool check_key(const PublicKey &key) {
    return crypto_ops::check_key(key);
  }

  /* Checks a private key and computes the corresponding public key.
   */
  inline bool secret_key_to_public_key(const SecretKey &sec, PublicKey &pub) {
    return crypto_ops::secret_key_to_public_key(sec, pub);
  }

  /* To generate an ephemeral key used to send money to:
   * * The sender generates a new key pair, which becomes the transaction key. The public transaction key is included in "extra" field.
   * * Both the sender and the receiver generate key derivation from the transaction key and the receivers' "view" key.
   * * The sender uses key derivation, the output index, and the receivers' "spend" key to derive an ephemeral public key.
   * * The receiver can either derive the public key (to check that the transaction is addressed to him) or the private key (to spend the money).
   */
  inline bool generate_key_derivation(const PublicKey &key1, const SecretKey &key2, KeyDerivation &derivation) {
    return crypto_ops::generate_key_derivation(key1, key2, derivation);
  }

  inline bool derive_public_key(const KeyDerivation &derivation, size_t output_index,
    const PublicKey &base, const uint8_t* prefix, size_t prefixLength, PublicKey &derived_key) {
    return crypto_ops::derive_public_key(derivation, output_index, base, prefix, prefixLength, derived_key);
  }

  inline bool derive_public_key(const KeyDerivation &derivation, size_t output_index,
    const PublicKey &base, PublicKey &derived_key) {
    return crypto_ops::derive_public_key(derivation, output_index, base, derived_key);
  }


  inline bool underive_public_key_and_get_scalar(const KeyDerivation &derivation, std::size_t output_index,
    const PublicKey &derived_key, PublicKey &base, EllipticCurveScalar &hashed_derivation) {
    return crypto_ops::underive_public_key_and_get_scalar(derivation, output_index, derived_key, base, hashed_derivation);
  }
  
  inline void derive_secret_key(const KeyDerivation &derivation, std::size_t output_index,
    const SecretKey &base, const uint8_t* prefix, size_t prefixLength, SecretKey &derived_key) {
    crypto_ops::derive_secret_key(derivation, output_index, base, prefix, prefixLength, derived_key);
  }

  inline void derive_secret_key(const KeyDerivation &derivation, std::size_t output_index,
    const SecretKey &base, SecretKey &derived_key) {
    crypto_ops::derive_secret_key(derivation, output_index, base, derived_key);
  }


  /* Inverse function of derive_public_key. It can be used by the receiver to find which "spend" key was used to generate a transaction. This may be useful if the receiver used multiple addresses which only differ in "spend" key.
   */
  inline bool underive_public_key(const KeyDerivation &derivation, size_t output_index,
    const PublicKey &derived_key, const uint8_t* prefix, size_t prefixLength, PublicKey &base) {
    return crypto_ops::underive_public_key(derivation, output_index, derived_key, prefix, prefixLength, base);
  }

  inline bool underive_public_key(const KeyDerivation &derivation, size_t output_index,
    const PublicKey &derived_key, PublicKey &base) {
    return crypto_ops::underive_public_key(derivation, output_index, derived_key, base);
  }

  /* Generation and checking of a standard signature.
   */
  inline void generate_signature(const Hash &prefix_hash, const PublicKey &pub, const SecretKey &sec, Signature &sig) {
    crypto_ops::generate_signature(prefix_hash, pub, sec, sig);
  }
  inline bool check_signature(const Hash &prefix_hash, const PublicKey &pub, const Signature &sig) {
    return crypto_ops::check_signature(prefix_hash, pub, sig);
  }

  /* Generation and checking of a tx proof; given a tx pubkey R, the recipient's view pubkey A, and the key
   * derivation D, the signature proves the knowledge of the tx secret key r such that R=r*G and D=r*A
   */
  inline void generate_tx_proof(const Hash &prefix_hash, const PublicKey &R, const PublicKey &A, const PublicKey &D, const SecretKey &r, Signature &sig) {
    crypto_ops::generate_tx_proof(prefix_hash, R, A, D, r, sig);
  }
  inline bool check_tx_proof(const Hash &prefix_hash, const PublicKey &R, const PublicKey &A, const PublicKey &D, const Signature &sig) {
    return crypto_ops::check_tx_proof(prefix_hash, R, A, D, sig);
  }	

  /* To send money to a key:
   * * The sender generates an ephemeral key and includes it in transaction output.
   * * To spend the money, the receiver generates a key image from it.
   * * Then he selects a bunch of outputs, including the one he spends, and uses them to generate a ring signature.
   * To check the signature, it is necessary to collect all the keys that were used to generate it. To detect double spends, it is necessary to check that each key image is used at most once.
   */
  inline void generate_key_image(const PublicKey &pub, const SecretKey &sec, KeyImage &image) {
    crypto_ops::generate_key_image(pub, sec, image);
  }

  inline KeyImage scalarmultKey(const KeyImage & P, const KeyImage & a) {
    return crypto_ops::scalarmultKey(P, a);
  }

  inline void hash_data_to_ec(const uint8_t* data, std::size_t len, PublicKey& key) {
    crypto_ops::hash_data_to_ec(data, len, key);
  }

  inline void generate_ring_signature(const Hash &prefix_hash, const KeyImage &image,
    const PublicKey *const *pubs, std::size_t pubs_count,
    const SecretKey &sec, std::size_t sec_index,
    Signature *sig) {
    crypto_ops::generate_ring_signature(prefix_hash, image, pubs, pubs_count, sec, sec_index, sig);
  }
  inline bool check_ring_signature(const Hash &prefix_hash, const KeyImage &image,
    const PublicKey *const *pubs, size_t pubs_count,
    const Signature *sig) {
    return crypto_ops::check_ring_signature(prefix_hash, image, pubs, pubs_count, sig);
  }

  /* Variants with vector<const PublicKey *> parameters.
   */
  inline void generate_ring_signature(const Hash &prefix_hash, const KeyImage &image,
    const std::vector<const PublicKey *> &pubs,
    const SecretKey &sec, size_t sec_index,
    Signature *sig) {
    generate_ring_signature(prefix_hash, image, pubs.data(), pubs.size(), sec, sec_index, sig);
  }
  inline bool check_ring_signature(const Hash &prefix_hash, const KeyImage &image,
    const std::vector<const PublicKey *> &pubs,
    const Signature *sig) {
    return check_ring_signature(prefix_hash, image, pubs.data(), pubs.size(), sig);
  }
  
  
  struct P3MulResult {
    const ge_p3 &p3;
    const EllipticCurveScalar &s;
  };
  struct P3MulResultG {
    const EllipticCurveScalar &s;
  };

  struct G3_type {};

  struct P3 {
    ge_p3 p3;

    constexpr P3() : p3{ {0}, {1, 0}, {1, 0}, {0} } {  // identity point
    }
    constexpr P3(const ge_p3 &other) : p3(other) {}
    P3(const G3_type &other);
    explicit P3(const EllipticCurvePoint &other) {
      if (ge_frombytes_vartime(&p3, reinterpret_cast<const unsigned char*>(&other)) != 0)
        throw Error("Public Key Invalid");
    }
    P3(const P3MulResult &other) { ge_scalarmult3(&p3, reinterpret_cast<const unsigned char*>(&other.s), &other.p3); }
    P3(const P3MulResultG &other) { ge_scalarmult_base(&p3, reinterpret_cast<const unsigned char*>(&other.s)); }
    bool frombytes_vartime(const EllipticCurvePoint &other);
    bool in_main_subgroup() const;
    P3 mul8() const;
  };

  inline PublicKey toBytes(const P3 &other) {
    PublicKey result;
    ge_p3_tobytes(reinterpret_cast<unsigned char*>(&result), &other.p3);
    return result;
  }

  template<typename T>
  T toBytes(const P3 &other) {
    T result;
    ge_p3_tobytes(reinterpret_cast<unsigned char*>(&result), &other.p3);
    return result;
  }

#if crypto_CRYPTO128
  constexpr G3_type P3_G{};
  constexpr P3 P3_I{ ge_p3{{0}, {1, 0}, {1, 0}, {0}} };
  constexpr P3 P3_H{ ge_p3{{1238364572342387, 511019468147982, 2037248038744755, 1790205373038460, 1715834670489604},
      {342040195458443, 1746005628638707, 1484107488641719, 1009716338237674, 354016121901985}, {1, 0, 0, 0, 0},
      {1908846832760925, 1960202731132578, 1264573804519519, 220054133280410, 1751608742250222}} };
  constexpr P3 G_p3{ ge_p3{{1738742601995546, 1146398526822698, 2070867633025821, 562264141797630, 587772402128613},
      {1801439850948184, 1351079888211148, 450359962737049, 900719925474099, 1801439850948198}, {1, 0, 0, 0, 0},
      {1841354044333475, 16398895984059, 755974180946558, 900171276175154, 1821297809914039}} };
#else
  constexpr G3_type P3_G{};
  constexpr P3 P3_I{ ge_p3{{0}, {1, 0}, {1, 0}, {0}} };
  constexpr P3 P3_H{ ge_p3{{7329926, -15101362, 31411471, 7614783, 27996851, -3197071, -11157635, -6878293, 466949, -7986503},
      {5858699, 5096796, 21321203, -7536921, -5553480, -11439507, -5627669, 15045946, 19977121, 5275251},
      {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
      {23443568, -5110398, -8776029, -4345135, 6889568, -14710814, 7474843, 3279062, 14550766, -7453428}} };
  constexpr P3 G_p3{
      ge_p3{{-14297830, -7645148, 16144683, -16471763, 27570974, -2696100, -26142465, 8378389, 20764389, 8758491},
          {-26843541, -6710886, 13421773, -13421773, 26843546, 6710886, -13421773, 13421773, -26843546, -6710886},
          {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
          {28827062, -6116119, -27349572, 244363, 8635006, 11264893, 19351346, 13413597, 16611511, -6414980}} };
#endif

  inline P3::P3(const G3_type &other) : p3(G_p3.p3) {}  // here, due to order of definitions

  inline P3 &operator*=(P3 &point_base, const EllipticCurveScalar &sec) {
    point_base = P3MulResult{ point_base.p3, sec };
    return point_base;
  }
  inline P3MulResultG operator*(const G3_type &, const EllipticCurveScalar &sec) { return P3MulResultG{ sec }; }
  inline P3MulResultG operator*(const EllipticCurveScalar &sec, const G3_type &) { return P3MulResultG{ sec }; }

  inline P3MulResult operator*(const P3 &point_base, const EllipticCurveScalar &sec) {
    return P3MulResult{ point_base.p3, sec };
  }
  inline P3MulResult operator*(const EllipticCurveScalar &sec, const P3 &point_base) {
    return P3MulResult{ point_base.p3, sec };
  }
  P3 operator-(const P3 &a, const P3 &b);
  inline P3 &operator-=(P3 &a, const P3 &b) {
    a = a - b;
    return a;
  }
  P3 operator+(const P3 &a, const P3 &b);
  inline P3 &operator+=(P3 &a, const P3 &b) {
    a = a + b;
    return a;
  }
  // + is fixed time by default
  inline P3 operator+(const P3MulResult &r1, const P3MulResult &r2) { return P3(r1) + P3(r2); }
  inline P3 operator+(const P3MulResultG &r1, const P3MulResult &r2) { return P3(r1) + P3(r2); }
  inline P3 operator+(const P3MulResult &r1, const P3MulResultG &r2) { return r2 + r1; }

  inline P3 vartime_add(const P3MulResult &r1, const P3MulResult &r2) {
    ge_dsmp dsm;
    ge_dsm_precomp(dsm, &r2.p3);
    P3 res_p3;
    ge_double_scalarmult_precomp_vartime3(&res_p3.p3, reinterpret_cast<const unsigned char*>(&r1.s), &r1.p3, reinterpret_cast<const unsigned char*>(&r2.s), dsm);
    return res_p3;
  }
  inline P3 vartime_add(const P3MulResultG &r1, const P3MulResult &r2) {
    P3 res_p3;
    ge_double_scalarmult_base_vartime3(&res_p3.p3, reinterpret_cast<const unsigned char*>(&r2.s), &r2.p3, reinterpret_cast<const unsigned char*>(&r1.s));
    return res_p3;
  }
  inline P3 vartime_add(const P3MulResult &r1, const P3MulResultG &r2) { return r2 + r1; }

  struct ScalarMulResult {
    const EllipticCurveScalar &a;
    const EllipticCurveScalar &b;
    operator SecretKey() {
      SecretKey result;
      sc_mul(reinterpret_cast<unsigned char*>(&result), reinterpret_cast<const unsigned char*>(&a), reinterpret_cast<const unsigned char*>(&b));
      return result;
    }
  };
  inline ScalarMulResult operator*(const EllipticCurveScalar &a, const EllipticCurveScalar &b) {
    return ScalarMulResult{ a, b };
  }
  inline EllipticCurveScalar &operator*=(EllipticCurveScalar &a, const EllipticCurveScalar &b) {
    a = ScalarMulResult{ a, b };
    return a;
  }

  inline SecretKey operator-(const EllipticCurveScalar &c, const ScalarMulResult &ab) {
    SecretKey result;
    sc_mulsub(reinterpret_cast<unsigned char*>(&result), reinterpret_cast<const unsigned char*>(&ab.a), reinterpret_cast<const unsigned char*>(&ab.b), reinterpret_cast<const unsigned char*>(&c));
    return result;
  }
  inline EllipticCurveScalar &operator-=(EllipticCurveScalar &c, const ScalarMulResult &ab) {
    c = c - ab;
    return c;
  }
  inline SecretKey operator-(const EllipticCurveScalar &a, const EllipticCurveScalar &b) {
    SecretKey result;
    sc_sub(reinterpret_cast<unsigned char*>(&result), reinterpret_cast<const unsigned char*>(&a), reinterpret_cast<const unsigned char*>(&b));
    return result;
  }
  inline EllipticCurveScalar &operator-=(EllipticCurveScalar &a, const EllipticCurveScalar &b) {
    a = a - b;
    return a;
  }
  inline SecretKey operator+(const EllipticCurveScalar &a, const EllipticCurveScalar &b) {
    SecretKey result;
    sc_add(reinterpret_cast<unsigned char*>(&result), reinterpret_cast<const unsigned char*>(&a), reinterpret_cast<const unsigned char*>(&b));
    return result;
  }
  inline EllipticCurveScalar &operator+=(EllipticCurveScalar &a, const EllipticCurveScalar &b) {
    a = a + b;
    return a;
  }

  PublicKey get_G();  // slow, for reference only
  PublicKey get_H();  // slow, for reference only

  void sc_invert(unsigned char *, const unsigned char *);

  inline SecretKey sc_invert(const unsigned char &sec) {
    SecretKey result;
    sc_invert(reinterpret_cast<unsigned char *>(&result), &sec);
    return result;
  }
  SecretKey sc_from_uint64(uint64_t val);

  inline void check_scalar(const EllipticCurveScalar &scalar) {
    if (!sc_check(reinterpret_cast<const unsigned char*>(&scalar)))
      throw Error("Secret Key Invalid");
  }

  P3 bytes_to_good_point_p3(const Hash &h);

  inline P3 hash_to_good_point_p3(const void *data, size_t length) {
    return bytes_to_good_point_p3(cn_fast_hash(data, length));
  }

  inline P3 hash_to_good_point_p3(const EllipticCurvePoint &key) {
    return hash_to_good_point_p3(key.data, sizeof(key.data));
  }

  bool p3_secret_key_to_public_key(const SecretKey &sec, PublicKey *pub);

  // Check a public key. Returns true if it is valid, false otherwise.
  bool key_isvalid(const EllipticCurvePoint &key);

  // Check if in the valid domain, alternative to Monero check: scalarmultKey(KeyImage, L) == I
  bool key_in_main_subgroup(const EllipticCurvePoint &key);

  // Checks a private key and the corresponding public key.
  bool keys_match(const SecretKey &secret_key, const PublicKey &expected_public_key);

  static inline const KeyImage &EllipticCurveScalar2KeyImage(const EllipticCurveScalar &k) { return (const KeyImage&)k; }
  static inline const PublicKey &EllipticCurveScalar2PublicKey(const EllipticCurveScalar &k) { return (const PublicKey&)k; }
  static inline const SecretKey &EllipticCurveScalar2SecretKey(const EllipticCurveScalar &k) { return (const SecretKey&)k; }

} // namespace Crypto

CRYPTO_MAKE_COMPARABLE(Crypto::Hash, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::EllipticCurveScalar, sodium_compare)
CRYPTO_MAKE_COMPARABLE(Crypto::EllipticCurvePoint, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::PublicKey, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::SecretKey, sodium_compare)
CRYPTO_MAKE_COMPARABLE(Crypto::KeyDerivation, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::KeyImage, std::memcmp)
CRYPTO_MAKE_COMPARABLE(Crypto::Signature, std::memcmp)

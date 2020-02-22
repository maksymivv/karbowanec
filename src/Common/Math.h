// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <ctype.h>
#include <algorithm>
#include <string>
#include <typeinfo>
#include <vector>
#include "exception.hpp"
#include "string.hpp"

namespace Common {

  template <class T>
  T medianValue(std::vector<T> &v) {
    if (v.empty())
      return T();

    if (v.size() == 1)
      return v[0];

    auto n = (v.size()) / 2;
    std::sort(v.begin(), v.end());
    if (v.size() % 2) { //1, 3, 5...
      return v[n];
    } else { //2, 4, 6...
      return (v[n - 1] + v[n]) / 2;
    }
  }

  template<typename Target, typename Source>
  void integer_cast_throw(const Source &arg) {
    throw std::out_of_range("Cannot convert value " + Common::to_string(arg) + " to integer in range [" +
      Common::to_string(std::numeric_limits<Target>::min()) + ".." +
      Common::to_string(std::numeric_limits<Target>::max()) + "]");
    //	throw std::out_of_range(
    //	    "Failed integer cast of " + Common::to_string(arg) + " to " + Common::demangle(typeid(Target).name()));
  }

  template<typename Target, typename Source>
  inline Target integer_cast_impl(const Source &arg, std::true_type, std::true_type) {
    // both unsigned
    if (arg > std::numeric_limits<Target>::max())
      integer_cast_throw<Target>(arg);
    return static_cast<Target>(arg);
  }

  template<typename Target, typename Source>
  inline Target integer_cast_impl(const Source &arg, std::false_type, std::false_type) {
    // both signed
    if (arg > std::numeric_limits<Target>::max())
      integer_cast_throw<Target>(arg);
    if (arg < std::numeric_limits<Target>::min())
      integer_cast_throw<Target>(arg);
    return static_cast<Target>(arg);
  }

  template<typename Target, typename Source>
  inline Target integer_cast_impl(const Source &arg, std::true_type, std::false_type) {
    // signed to unsigned
    typedef typename std::make_unsigned<Source>::type USource;
    if (arg < 0)
      integer_cast_throw<Target>(arg);
    if (static_cast<USource>(arg) > std::numeric_limits<Target>::max())
      integer_cast_throw<Target>(arg);
    return static_cast<Target>(arg);
  }

  template<typename Target, typename Source>
  inline Target integer_cast_impl(const Source &arg, std::false_type, std::true_type) {
    // unsigned to signed
    typedef typename std::make_unsigned<Target>::type UTarget;
    if (arg > static_cast<UTarget>(std::numeric_limits<Target>::max()))
      integer_cast_throw<Target>(arg);
    return static_cast<Target>(arg);
  }

  template<typename Target, typename Source>  // source integral
  inline Target integer_cast_is_integral(const Source &arg, std::true_type) {
    return integer_cast_impl<Target, Source>(arg, std::is_unsigned<Target>{}, std::is_unsigned<Source>{});
  }

  inline bool has_sign(const std::string &arg) {
    size_t pos = 0;
    while (pos != arg.size() && isspace(arg[pos]))
      pos += 1;
    return pos != arg.size() && arg[pos] == '-';
  }

  inline bool has_tail(const std::string &arg, size_t &pos) {
    while (pos != arg.size() && isspace(arg[pos]))
      pos += 1;
    return pos != arg.size();
  }

  template<typename Target, typename Source>  // source not integral (string convertible)
  inline Target integer_cast_is_integral(const Source &arg, std::false_type) {
    const std::string &sarg = arg;          // creates tmp object if neccessary
    if (std::is_unsigned<Target>::value) {  // Crazy stupid C++ standard :(
      if (has_sign(sarg))
        throw std::out_of_range("Cannot convert string '" + sarg + "' to integer, must be >= 0");
      size_t pos = 0;
      auto val = std::stoull(sarg, &pos);
      if (has_tail(sarg, pos))
        throw std::out_of_range("Cannot convert string '" + sarg + "' to integer, excess characters not allowed");
      return integer_cast_is_integral<Target>(val, std::true_type{});
    }
    size_t pos = 0;
    auto val = std::stoll(sarg, &pos);
    if (has_tail(sarg, pos))
      throw std::out_of_range("Cannot convert string '" + sarg + "' to integer, excess characters '" +
        sarg.substr(pos) + "' not allowed");
    return integer_cast_is_integral<Target>(val, std::true_type{});
  }

  template<typename Target, typename Source>
  inline Target integer_cast(const Source &arg) {
    static_assert(
      std::is_integral<Target>::value, "Target type must be integral, source either integral or string convertible");
    return integer_cast_is_integral<Target, Source>(arg, std::is_integral<Source>{});
  }
}  // namespace common

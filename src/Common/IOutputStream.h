// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
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
#include <cstdint>
#include <stdexcept>
#include <string>
#include "BinaryArray.hpp"
#include "Math.h"

namespace Common {

class IOutputStream {
public:
  virtual ~IOutputStream() { }
  virtual size_t writeSome(const void* data, size_t size) = 0;
  void write(const void *data, size_t size);
  void write(const CryptoNote::BinaryArray &data);
  void write(const std::string &data);
  void write_byte(uint8_t b) { write(&b, 1); }
  void write_varint(uint64_t value);
};

}

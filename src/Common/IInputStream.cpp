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

#include "IInputStream.h"
#include "Streams.hpp"
#include <algorithm>
#include <stdexcept>
#include <CryptoNote.h>
#include "BinaryArray.hpp"
#include "Varint.hpp"

using namespace Common;

void IInputStream::read(void *data, size_t count) {
  while (count != 0) {
    size_t rc = readSome(data, count);
    if (rc == 0)
      throw StreamError("IInputStream reading from empty stream");
    data = reinterpret_cast<char *>(data) + rc;
    count -= rc;
  }
}

static const size_t CHUNK = 1024 * 1024;
// We read sized entities in chunks to prevent over-sized allocation attacks

void IInputStream::read(CryptoNote::BinaryArray &data, size_t size) {
  data.resize(std::min(CHUNK, size));
  read(data.data(), data.size());
  while (data.size() != size) {
    size_t add = std::min(CHUNK, size - data.size());
    data.resize(data.size() + add);
    read(data.data() + data.size() - add, add);
  }
}

void IInputStream::read(std::string &data, size_t size) {
  data.resize(std::min(CHUNK, size));
  read(&data[0], data.size());
  while (data.size() != size) {
    size_t add = std::min(CHUNK, size - data.size());
    data.resize(data.size() + add);
    read(&data[0] + data.size() - add, add);
  }
}

template<typename T>
void read_varint_helper(IInputStream &in, T &value) {
  T temp = 0;
  for (uint8_t shift = 0;; shift += 7) {
    uint8_t piece = in.read_byte();
    if (shift >= sizeof(temp) * 8 - 7 && piece >= 1 << (sizeof(temp) * 8 - shift))
      throw std::runtime_error("read_varint, value overflow");
    temp |= static_cast<T>(piece & 0x7f) << shift;
    if ((piece & 0x80) == 0) {
      if (piece == 0 && shift != 0)
        throw std::runtime_error("read_varint, invalid value representation");
      break;
    }
  }
  value = temp;
}
uint8_t IInputStream::read_byte() {
  uint8_t result = 0;
  read(&result, 1);
  return result;
}

uint64_t IInputStream::read_varint64() {
  uint64_t result = 0;
  read_varint_helper(*this, result);
  return result;
}

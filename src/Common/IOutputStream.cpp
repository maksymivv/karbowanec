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

#include "IOutputStream.h"

#include "Streams.hpp"
#include <algorithm>
#include <stdexcept>
#include <CryptoNote.h>
#include "BinaryArray.hpp"
#include "Varint.hpp"

using namespace Common;

void IOutputStream::write(const CryptoNote::BinaryArray &data) { write(data.data(), data.size()); }

void IOutputStream::write(const std::string &data) { write(data.data(), data.size()); }

void IOutputStream::write(const void *data, size_t size) {
	while (size != 0) {
		size_t wc = writeSome(data, size);
		if (wc == 0)
			throw StreamError("IOutputStream error writing to full stream");
		data = reinterpret_cast<const char *>(data) + wc;
		size -= wc;
	}
}

void IOutputStream::write_varint(uint64_t value) {
  uint8_t buf[10];  // enough to store uint64_t
  uint8_t *end = buf;
  Common::write_varint(end, value);
  write(buf, end - buf);
}
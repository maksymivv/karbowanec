// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stdexcept>

namespace Common {
// read_some and write_some are allowed to read/write as many bytes as convenient, returning bytes read/written
// read and write are obliged to read/write all data and throw if it is not possible

class StreamError : public std::runtime_error {
public:
	using std::runtime_error::runtime_error;
};
class StreamErrorFileExists : public StreamError {
public:
	using StreamError::StreamError;
};
}  // namespace common

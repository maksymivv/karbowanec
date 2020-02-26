// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <string>
#include <CryptoNote.h>
#include "Nocopy.hpp"
#include "StreamTools.h"
#include "IInputStream.h"
#include "IOutputStream.h"
#include "PathTools.h"

namespace Common {

enum OpenMode {
	O_READ_EXISTING,  // will fail if file does not exist
	O_CREATE_ALWAYS,  // will create file if needed and then truncate it
	O_CREATE_NEW,     // will fail if file exists
	O_OPEN_ALWAYS,    // will be created if needed
	O_OPEN_EXISTING   // will fail if file does not exist
};                    // to append, use O_OPEN_ALWAYS or O_OPEN_EXISTING, then seek(0, SEEK_END)

class FileStream : public Common::IOutputStream, public Common::IInputStream, private Common::Nocopy {
public:
	explicit FileStream(const std::string &filename, OpenMode mode);
	~FileStream() override;
	size_t writeSome(const void *data, size_t size) override;
	size_t readSome(void *data, size_t size) override;

	uint64_t seek(uint64_t pos, int whence);  // SEEK_SET, SEEK_CUR, SEEK_END
	uint64_t tellp() const { return const_cast<FileStream *>(this)->seek(0, SEEK_CUR); }
	void fsync();                  // top reason for existence of this class
	void truncate(uint64_t size);  // also sets pointer to the new end of file

#ifdef _WIN32
	static std::wstring utf8_to_utf16(const std::string &str);  // Used by various Windows API wrappers
	static std::string utf16_to_utf8(const std::wstring &str);  // Used by various Windows API wrappers
#endif
private:
	explicit FileStream();
	bool try_open(const std::string &filename, OpenMode mode, bool *file_existed = nullptr);
	// We want those funs to use FileStream without exceptions (greatly hinders debugging)
	friend bool Platform::load_file(const std::string &filepath, std::string &buf);
	friend bool Platform::load_file(const std::string &filepath, CryptoNote::BinaryArray &buf);
#ifdef _WIN32
	void *handle;  // HANDLE, cannot initialize hre because do not want to guess what is INVALID_HANDLE_VALUE
#else
	int fd = -1;
#endif
};
}  // namespace Platform

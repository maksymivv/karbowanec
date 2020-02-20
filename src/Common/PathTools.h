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

#include <string>
#include <vector>
#include <CryptoNote.h>

namespace Common {

std::string NativePathToGeneric(const std::string& nativePath);

std::string GetPathDirectory(const std::string& path);
std::string GetPathFilename(const std::string& path);
void SplitPath(const std::string& path, std::string& directory, std::string& filename);

std::string CombinePath(const std::string& path1, const std::string& path2);
std::string GetExtension(const std::string& path);
std::string RemoveExtension(const std::string& path);
std::string ReplaceExtenstion(const std::string& path, const std::string& extension);
bool HasParentPath(const std::string& path);

}

#ifdef __APPLE__
#include "TargetConditionals.h"
#endif

// For documentation
#if TARGET_OS_MAC
#define platform_DEFAULT_DATA_FOLDER_PATH_PREFIX "~/Library/Application Support/"
#elif defined(_WIN32)
#define platform_DEFAULT_DATA_FOLDER_PATH_PREFIX "%appdata%/"
#else  // defined(__linux__) and unknown platforms
#define platform_DEFAULT_DATA_FOLDER_PATH_PREFIX "~/."
#endif

namespace platform {

// New method
// Windows < Vista: C:\Documents and Settings\Username\Application Data/<app_name>
// Windows >= Vista: C:\Users\Username\AppData\Local/<app_name>
// Mac: fullpath of ~/Library/Application Support/<app_name>
// Unix: fullpath of ~/.<app_name>
std::string get_app_data_folder(const std::string &app_name);

std::string get_os_version_string();
std::string get_platform_name();
std::string normalize_folder(const std::string &path);
std::string expand_path(const std::string &path);
bool folder_exists(const std::string &path);
bool create_folder_if_necessary(const std::string &path);   // Only last element
bool create_folders_if_necessary(const std::string &path);  // Recursively all elements
bool atomic_replace_file(const std::string &from_path, const std::string &to_path);
bool copy_file(const std::string &from_path, const std::string &to_path);
bool remove_file(const std::string &path);
std::vector<std::string> get_filenames_in_folder(const std::string &path);
std::string get_filename_without_folder(const std::string &path);
// std::string strip_trailing_slashes(const std::string & path);
bool load_file(const std::string &filepath, std::string &buf);
bool load_file(const std::string &filepath, CryptoNote::BinaryArray &buf);
bool save_file(const std::string &filepath, const void *buf, size_t size);
bool atomic_save_file(const std::string &filepath, const void *buf, size_t size, const std::string &tmp_filepath);
inline bool save_file(const std::string &filepath, const std::string &buf) {
	return save_file(filepath, buf.data(), buf.size());
}
}  // namespace platform
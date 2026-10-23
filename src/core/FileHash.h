#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "core/Hashes.h"

struct FileHashResult
{
    std::wstring hashes[kHashAlgCount];   // lowercase hex, for the selected algorithms
    std::wstring error;                   // set when HashFile returns false
    uint64_t bytesRead = 0;
};

// Reads a file once and feeds it to every selected algorithm. buffer is the
// read buffer (reused between calls). cancel and progress are optional.
bool HashFile(const std::wstring& path, const HashOptions& options, FileHashResult& result,
              std::vector<BYTE>& buffer, const std::atomic<bool>* cancel = nullptr,
              std::atomic<uint64_t>* progress = nullptr);

// Hashes an in-memory buffer with every selected algorithm.
void HashBytes(const std::vector<BYTE>& data, const HashOptions& options, FileHashResult& result);

struct FoundFile
{
    std::wstring relPath;   // relative to the listed folder
    uint64_t size;
};

// Lists files in root matching pattern ("*" for all), descending into
// subfolders (junctions and symlinks are skipped) when recurse is set.
// The result is sorted in Explorer order. Stops early when cancel is set.
void ListFiles(const std::wstring& root, const std::wstring& pattern, bool recurse,
               std::vector<FoundFile>& out, const std::atomic<bool>* cancel = nullptr,
               std::atomic<size_t>* counter = nullptr);

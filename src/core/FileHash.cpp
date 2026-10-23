#include "core/FileHash.h"

#include <shlwapi.h>

#include <algorithm>
#include <exception>
#include <memory>

#include "common/Util.h"

#pragma comment(lib, "shlwapi.lib")

namespace {

void CreateHashers(const HashOptions& options, std::unique_ptr<Hasher> (&hashers)[kHashAlgCount],
                   FileHashResult& result)
{
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        if (!options.selected[i]) continue;
        hashers[i] = CreateHasher(static_cast<HashAlg>(i), options.Key());
        if (!hashers[i])
            result.hashes[i] = L"(HMAC not supported)";
    }
}

void FinishHashers(std::unique_ptr<Hasher> (&hashers)[kHashAlgCount], FileHashResult& result)
{
    for (int i = 0; i < kHashAlgCount; ++i)
        if (hashers[i])
            result.hashes[i] = hashers[i]->FinishText();
}

bool IsCancelled(const std::atomic<bool>* cancel)
{
    return cancel && cancel->load();
}

// Lists one folder: matching files go to out, subfolders to subfolders.
void ListOneFolder(const std::wstring& root, const std::wstring& rel, const std::wstring& pattern, bool recurse,
                   std::vector<FoundFile>& out, std::vector<std::wstring>& subfolders,
                   const std::atomic<bool>* cancel, std::atomic<size_t>* counter)
{
    const bool all = pattern == L"*";
    WIN32_FIND_DATAW fd;

    // Pass 1: matching files (and, for "*", the subfolders too)
    std::wstring search = LongPath(root + L"\\" + rel + pattern);
    HANDLE find = FindFirstFileExW(search.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch,
        nullptr, FIND_FIRST_EX_LARGE_FETCH);
    if (find != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (IsCancelled(cancel))
                break;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (all && recurse && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                    subfolders.push_back(rel + fd.cFileName + L"\\");
            }
            else
            {
                out.push_back({ rel + fd.cFileName, (uint64_t(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow });
                if (counter) ++*counter;
            }
        } while (FindNextFileW(find, &fd));
        FindClose(find);
    }

    // Pass 2: with a narrower pattern, find the subfolders separately
    if (recurse && !all && !IsCancelled(cancel))
    {
        search = LongPath(root + L"\\" + rel + L"*");
        find = FindFirstFileExW(search.c_str(), FindExInfoBasic, &fd, FindExSearchLimitToDirectories,
            nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (find != INVALID_HANDLE_VALUE)
        {
            do
            {
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                    wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0)
                    subfolders.push_back(rel + fd.cFileName + L"\\");
            } while (FindNextFileW(find, &fd));
            FindClose(find);
        }
    }
}

} // namespace

bool HashFile(const std::wstring& path, const HashOptions& options, FileHashResult& result,
              std::vector<BYTE>& buffer, const std::atomic<bool>* cancel, std::atomic<uint64_t>* progress)
{
    try
    {
        std::unique_ptr<Hasher> hashers[kHashAlgCount];
        CreateHashers(options, hashers, result);

        HANDLE file = CreateFileW(LongPath(path).c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            result.error = ErrorMessage(GetLastError());
            return false;
        }

        DWORD readError = ERROR_SUCCESS;
        while (!IsCancelled(cancel))
        {
            DWORD read = 0;
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
            {
                readError = GetLastError();
                break;
            }
            if (read == 0)
                break;
            for (auto& h : hashers)
                if (h) h->Update(buffer.data(), read);
            result.bytesRead += read;
            if (progress) *progress += read;
        }
        CloseHandle(file);

        if (IsCancelled(cancel))
        {
            result.error = L"Cancelled";
            return false;
        }
        if (readError != ERROR_SUCCESS)
        {
            result.error = ErrorMessage(readError);
            return false;
        }
        FinishHashers(hashers, result);
        return true;
    }
    catch (const std::exception&)
    {
        result.error = L"Hash calculation failed";
        return false;
    }
}

void HashBytes(const std::vector<BYTE>& data, const HashOptions& options, FileHashResult& result)
{
    std::unique_ptr<Hasher> hashers[kHashAlgCount];
    CreateHashers(options, hashers, result);
    for (auto& h : hashers)
        if (h) h->Update(data.data(), data.size());
    FinishHashers(hashers, result);
    result.bytesRead = data.size();
}

void ListFiles(const std::wstring& root, const std::wstring& pattern, bool recurse,
               std::vector<FoundFile>& out, const std::atomic<bool>* cancel, std::atomic<size_t>* counter)
{
    size_t first = out.size();
    // A work list instead of recursion: very deep folder trees cannot run
    // out of stack. The order does not matter, the result is sorted below.
    std::vector<std::wstring> pending{ L"" };
    while (!pending.empty() && !IsCancelled(cancel))
    {
        std::wstring rel = std::move(pending.back());
        pending.pop_back();
        ListOneFolder(root, rel, pattern, recurse, out, pending, cancel, counter);
    }
    std::sort(out.begin() + first, out.end(), [](const FoundFile& a, const FoundFile& b) {
        return StrCmpLogicalW(a.relPath.c_str(), b.relPath.c_str()) < 0;
    });
}

#include "Cli.h"

#include <windows.h>
#include <shlwapi.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "FileHash.h"
#include "Hashes.h"
#include "Util.h"
#include "version.h"

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailed = 1;
constexpr int kExitUsage = 2;
constexpr unsigned kMaxThreads = 8;
constexpr size_t kReadBufferSize = 1 << 20;

const wchar_t kBanner[] = L"HashCalc " VERSION_STR L" - file and text hash calculator\n\n";

const wchar_t kUsage[] =
LR"(Usage: HashCalc [options] <file | folder | wildcard> ...
       HashCalc [options] -s <text>
       HashCalc -c <checksum file>

Algorithms (default: SHA256):
  -md5 -md4 -md2 -sha1 -sha256 -sha384 -sha512 -ripemd160
  -tiger -panama -crc32 -adler32 -edonkey
  -a <list>       comma-separated list, e.g. -a md5,sha1,sha256
  -all            all algorithms

Input:
  -r              include subfolders for folders and wildcards
  -s <text>       hash a text string (UTF-8)
  -x <hex>        hash a hex string
  -hmac <key>     HMAC with a text key
  -hmachex <key>  HMAC with a hex key

Output:
  -sum            checksum file format "<hash> *<file>" (one algorithm)
  -csv            CSV: file, size, one column per algorithm
  -bare           hashes only, one line per input
  -upper          uppercase hex digits
  -o <file>       write the results to a file (UTF-8)
  -nologo         do not print the banner (also -nobanner)
  -t <n>          files hashed in parallel (default: CPU count, max 8)

Verify:
  -c <file>       check the files listed in a checksum file
                  (md5sum / sha256sum / BSD format; relative paths are looked up
                  in the current folder, then next to the checksum file)

  -h, -?          show this help

Exit code: 0 = success, 1 = some files failed or did not match, 2 = invalid arguments.

Examples:
  HashCalc setup.exe
  HashCalc -md5 -sha256 -nologo *.iso
  HashCalc -sha256 -sum -r D:\Release > release.sha256
  HashCalc -c release.sha256
  HashCalc -all -s "hello world"
)";

enum class Format { Default, Sum, Csv, Bare };

struct CliOptions
{
    HashOptions hash;
    bool anyAlgorithm = false;
    bool recurse = false;
    bool banner = true;
    bool upper = false;
    Format format = Format::Default;
    unsigned threads = 0;
    std::wstring outFile;
    std::wstring checkFile;
    std::vector<std::wstring> texts;
    std::vector<std::wstring> hexes;
    std::vector<std::wstring> inputs;
};

// ---------------------------------------------------------------------------
// Console / file output: UTF-16 to a console, UTF-8 when redirected.
// ---------------------------------------------------------------------------
class Writer
{
public:
    explicit Writer(DWORD stdHandle)
    {
        m_handle = GetStdHandle(stdHandle);
        if (m_handle == nullptr || m_handle == INVALID_HANDLE_VALUE)
        {
            // GUI process attached to a console: no inherited handles.
            m_handle = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, nullptr,
                OPEN_EXISTING, 0, nullptr);
            m_owned = true;
        }
        DWORD mode = 0;
        m_console = Valid() && GetConsoleMode(m_handle, &mode);
    }

    ~Writer()
    {
        Flush();
        if (m_owned && Valid())
            CloseHandle(m_handle);
    }

    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;

    bool OpenFile(const std::wstring& path)
    {
        HANDLE file = CreateFileW(LongPath(path).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        Flush();
        if (m_owned && Valid())
            CloseHandle(m_handle);
        m_handle = file;
        m_owned = true;
        m_console = false;
        return true;
    }

    void Write(const std::wstring& text)
    {
        m_buffer += text;
        if (m_buffer.size() >= 16384)
            Flush();
    }

    void Flush()
    {
        if (m_buffer.empty())
            return;
        if (Valid())
        {
            DWORD written = 0;
            if (m_console)
                WriteConsoleW(m_handle, m_buffer.data(), static_cast<DWORD>(m_buffer.size()), &written, nullptr);
            else
            {
                std::vector<BYTE> utf8 = ToUtf8(m_buffer);
                WriteFile(m_handle, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
            }
        }
        m_buffer.clear();
    }

private:
    bool Valid() const { return m_handle && m_handle != INVALID_HANDLE_VALUE; }

    HANDLE m_handle = nullptr;
    bool m_owned = false;
    bool m_console = false;
    std::wstring m_buffer;
};

struct Console
{
    Writer out{ STD_OUTPUT_HANDLE };
    Writer err{ STD_ERROR_HANDLE };

    void Out(const std::wstring& s) { out.Write(s); }

    void Error(const std::wstring& s)
    {
        out.Flush();
        err.Write(L"HashCalc: " + s + L"\n");
        err.Flush();
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
std::wstring Lower(std::wstring s)
{
    CharLowerBuffW(s.data(), static_cast<DWORD>(s.size()));
    return s;
}

bool ParseAlgorithm(std::wstring name, int& alg)
{
    name = Lower(name);
    name.erase(std::remove_if(name.begin(), name.end(), [](wchar_t c) { return c == L'-' || c == L'_'; }), name.end());
    if (name == L"ed2k" || name == L"emule") name = L"edonkey";
    if (name == L"ripemd" || name == L"rmd160") name = L"ripemd160";
    if (name == L"tiger192") name = L"tiger";
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        if (Lower(HashAlgName(static_cast<HashAlg>(i))) == name)
        {
            alg = i;
            return true;
        }
    }
    return false;
}

std::vector<std::wstring> Split(const std::wstring& s, const wchar_t* separators)
{
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= s.size())
    {
        size_t end = s.find_first_of(separators, start);
        if (end == std::wstring::npos) end = s.size();
        if (end > start) parts.push_back(s.substr(start, end - start));
        start = end + 1;
    }
    return parts;
}

std::wstring CsvField(const std::wstring& s)
{
    if (s.find_first_of(L",\"\r\n") == std::wstring::npos)
        return s;
    std::wstring out = L"\"";
    for (wchar_t c : s)
    {
        if (c == L'"') out += L'"';
        out += c;
    }
    return out + L"\"";
}

bool IsHex(const std::wstring& s)
{
    return !s.empty() && std::all_of(s.begin(), s.end(), [](wchar_t c) { return iswxdigit(c) != 0; });
}

std::wstring TrimSlashes(std::wstring s)
{
    while (s.size() > 1 && (s.back() == L'\\' || s.back() == L'/'))
        s.pop_back();
    return s;
}

// Runs work(i) on a thread pool and calls print(i) in input order as results arrive.
template <class Work, class Print>
void RunOrdered(size_t count, unsigned threads, Work work, Print print)
{
    if (count == 0)
        return;
    threads = static_cast<unsigned>(std::max<size_t>(1, std::min<size_t>(threads, count)));

    std::vector<char> ready(count, 0);
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<size_t> next{ 0 };

    auto worker = [&] {
        std::vector<BYTE> buffer(kReadBufferSize);
        for (;;)
        {
            size_t i = next++;
            if (i >= count)
                return;
            work(i, buffer);
            {
                std::lock_guard<std::mutex> lock(mutex);
                ready[i] = 1;
            }
            cv.notify_all();
        }
    };

    std::vector<std::thread> pool;
    for (unsigned t = 0; t < threads; ++t)
        pool.emplace_back(worker);
    for (size_t i = 0; i < count; ++i)
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&] { return ready[i] != 0; });
        lock.unlock();
        print(i);
    }
    for (std::thread& t : pool)
        t.join();
}

unsigned DefaultThreads(const CliOptions& opt)
{
    if (opt.threads)
        return opt.threads;
    return std::max(1u, std::min(std::thread::hardware_concurrency(), kMaxThreads));
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
bool ParseArgs(int argc, wchar_t** argv, CliOptions& opt, Console& con, bool& showHelp)
{
    auto next = [&](int& i, const std::wstring& option, std::wstring& value) {
        if (i + 1 >= argc)
        {
            con.Error(L"option " + option + L" needs a value");
            return false;
        }
        value = argv[++i];
        return true;
    };
    auto select = [&](int alg) {
        opt.hash.selected[alg] = true;
        opt.anyAlgorithm = true;
    };

    for (int i = 1; i < argc; ++i)
    {
        std::wstring arg = argv[i];
        bool isOption = arg.size() > 1 && (arg[0] == L'-' || arg[0] == L'/');
        if (!isOption)
        {
            opt.inputs.push_back(arg);
            continue;
        }

        std::wstring name = Lower(arg.substr(arg.find_first_not_of(L"-/")));
        std::wstring value;
        int alg = 0;

        if (name == L"h" || name == L"?" || name == L"help")
            showHelp = true;
        else if (name == L"all")
            for (int a = 0; a < kHashAlgCount; ++a) select(a);
        else if (name == L"a" || name == L"alg" || name == L"algorithms")
        {
            if (!next(i, arg, value)) return false;
            for (const std::wstring& part : Split(value, L",; "))
            {
                if (!ParseAlgorithm(part, alg))
                {
                    con.Error(L"unknown algorithm: " + part);
                    return false;
                }
                select(alg);
            }
        }
        else if (name == L"r" || name == L"recurse")
            opt.recurse = true;
        else if (name == L"s" || name == L"text")
        {
            if (!next(i, arg, value)) return false;
            opt.texts.push_back(value);
        }
        else if (name == L"x" || name == L"hex")
        {
            if (!next(i, arg, value)) return false;
            opt.hexes.push_back(value);
        }
        else if (name == L"hmac")
        {
            if (!next(i, arg, value)) return false;
            opt.hash.hmac = true;
            opt.hash.key = ToUtf8(value);
        }
        else if (name == L"hmachex")
        {
            if (!next(i, arg, value)) return false;
            opt.hash.hmac = true;
            if (!ParseHex(value, opt.hash.key))
            {
                con.Error(L"the HMAC key is not a valid hex string");
                return false;
            }
        }
        else if (name == L"sum")
            opt.format = Format::Sum;
        else if (name == L"csv")
            opt.format = Format::Csv;
        else if (name == L"bare")
            opt.format = Format::Bare;
        else if (name == L"upper" || name == L"u")
            opt.upper = true;
        else if (name == L"o" || name == L"out")
        {
            if (!next(i, arg, opt.outFile)) return false;
        }
        else if (name == L"nologo" || name == L"nobanner")
            opt.banner = false;
        else if (name == L"t" || name == L"threads")
        {
            if (!next(i, arg, value)) return false;
            int n = _wtoi(value.c_str());
            if (n < 1 || n > 64)
            {
                con.Error(L"thread count must be between 1 and 64");
                return false;
            }
            opt.threads = static_cast<unsigned>(n);
        }
        else if (name == L"c" || name == L"check")
        {
            if (!next(i, arg, opt.checkFile)) return false;
        }
        else if (ParseAlgorithm(name, alg))
            select(alg);
        else
        {
            con.Error(L"unknown option: " + arg + L"  (use -h for help)");
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Hashing files and strings
// ---------------------------------------------------------------------------
struct Item
{
    std::wstring display;          // name as printed
    std::wstring path;             // file to read, empty for in-memory data
    std::vector<BYTE> data;
    bool isData = false;
    uint64_t size = 0;
    FileHashResult result;
    bool ok = false;
};

void AddInput(const std::wstring& arg, bool recurse, std::vector<Item>& items, Console& con, int& failures)
{
    std::vector<FoundFile> found;
    if (arg.find_first_of(L"*?") != std::wstring::npos)
    {
        size_t slash = arg.find_last_of(L"\\/");
        std::wstring dir = slash == std::wstring::npos ? L"." : arg.substr(0, slash);
        std::wstring prefix = slash == std::wstring::npos ? L"" : arg.substr(0, slash + 1);
        if (dir.empty() || (dir.size() == 2 && dir[1] == L':'))
            dir += L"\\";   // "\*.txt" or "C:*.txt"
        ListFiles(TrimSlashes(dir), arg.substr(slash == std::wstring::npos ? 0 : slash + 1), recurse, found);
        if (found.empty())
        {
            con.Error(arg + L": no matching files");
            ++failures;
        }
        for (const FoundFile& f : found)
        {
            Item item;
            item.display = prefix + f.relPath;
            item.path = slash == std::wstring::npos ? f.relPath : TrimSlashes(dir) + L"\\" + f.relPath;
            item.size = f.size;
            items.push_back(std::move(item));
        }
    }
    else if (IsDirectory(arg))
    {
        std::wstring dir = TrimSlashes(arg);
        ListFiles(dir, L"*", recurse, found);
        if (found.empty())
            con.Error(arg + (recurse ? L": folder is empty" : L": no files in folder (use -r to include subfolders)"));
        for (const FoundFile& f : found)
        {
            Item item;
            item.display = item.path = dir + L"\\" + f.relPath;
            item.size = f.size;
            items.push_back(std::move(item));
        }
    }
    else
    {
        Item item;
        item.display = item.path = arg;
        items.push_back(std::move(item));
    }
}

std::wstring Hex(const CliOptions& opt, const std::wstring& hash)
{
    if (!opt.upper || hash.empty() || hash[0] == L'(')
        return hash;
    std::wstring s = hash;
    CharUpperBuffW(s.data(), static_cast<DWORD>(s.size()));
    return s;
}

int RunHash(CliOptions& opt, Console& con)
{
    std::vector<int> algs;
    size_t nameWidth = 0;
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        if (!opt.hash.selected[i]) continue;
        algs.push_back(i);
        nameWidth = std::max(nameWidth, wcslen(HashAlgName(static_cast<HashAlg>(i))));
    }
    if (opt.format == Format::Sum && algs.size() != 1)
    {
        con.Error(L"-sum needs exactly one algorithm");
        return kExitUsage;
    }

    int failures = 0;
    std::vector<Item> items;
    for (const std::wstring& text : opt.texts)
    {
        Item item;
        item.display = L"\"" + text + L"\"";
        item.data = ToUtf8(text);
        item.isData = true;
        items.push_back(std::move(item));
    }
    for (const std::wstring& hex : opt.hexes)
    {
        Item item;
        if (!ParseHex(hex, item.data))
        {
            con.Error(L"not a valid hex string: " + hex);
            return kExitUsage;
        }
        item.display = L"hex:" + hex;
        item.isData = true;
        items.push_back(std::move(item));
    }
    for (const std::wstring& input : opt.inputs)
        AddInput(input, opt.recurse, items, con, failures);

    if (opt.banner && opt.format == Format::Default)
        con.Out(kBanner);
    if (opt.format == Format::Csv)
    {
        std::wstring header = L"File,Size";
        for (int alg : algs)
            header += L"," + std::wstring(HashAlgName(static_cast<HashAlg>(alg)));
        con.Out(header + L",Error\n");
    }

    auto work = [&](size_t i, std::vector<BYTE>& buffer) {
        Item& item = items[i];
        if (item.isData)
        {
            HashBytes(item.data, opt.hash, item.result);
            item.ok = true;
        }
        else
            item.ok = HashFile(item.path, opt.hash, item.result, buffer);
        item.size = std::max<uint64_t>(item.size, item.result.bytesRead);
        if (item.isData) item.size = item.data.size();
    };

    auto print = [&](size_t i) {
        Item& item = items[i];
        if (!item.ok) ++failures;

        switch (opt.format)
        {
        case Format::Default:
        {
            std::wstring block = item.display + L"\n";
            if (!item.ok)
                block += L"  Error: " + item.result.error + L"\n";
            else
                for (int alg : algs)
                {
                    std::wstring name = HashAlgName(static_cast<HashAlg>(alg));
                    block += L"  " + name + std::wstring(nameWidth - name.size(), L' ') + L"  "
                        + Hex(opt, item.result.hashes[alg]) + L"\n";
                }
            con.Out(block + L"\n");
            break;
        }
        case Format::Sum:
            if (item.ok)
                con.Out(Hex(opt, item.result.hashes[algs[0]]) + L" *" + item.display + L"\n");
            else
                con.Error(item.display + L": " + item.result.error);
            break;
        case Format::Csv:
        {
            std::wstring row = CsvField(item.display) + L"," + std::to_wstring(item.size);
            for (int alg : algs)
                row += L"," + (item.ok ? Hex(opt, item.result.hashes[alg]) : L"");
            con.Out(row + L"," + CsvField(item.ok ? L"" : item.result.error) + L"\n");
            break;
        }
        case Format::Bare:
            if (item.ok)
            {
                std::wstring line;
                for (int alg : algs)
                    line += (line.empty() ? L"" : L" ") + Hex(opt, item.result.hashes[alg]);
                con.Out(line + L"\n");
            }
            else
                con.Error(item.display + L": " + item.result.error);
            break;
        }
        item = Item();   // free memory as we go
    };

    RunOrdered(items.size(), DefaultThreads(opt), work, print);
    return failures ? kExitFailed : kExitOk;
}

// ---------------------------------------------------------------------------
// Verify (-c)
// ---------------------------------------------------------------------------
bool ReadTextFile(const std::wstring& path, std::wstring& text)
{
    HANDLE file = CreateFileW(LongPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER size = {};
    GetFileSizeEx(file, &size);
    std::vector<BYTE> data(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    bool ok = data.empty() || (ReadFile(file, data.data(), static_cast<DWORD>(data.size()), &read, nullptr) && read == data.size());
    CloseHandle(file);
    if (!ok)
        return false;

    if (data.size() >= 2 && data[0] == 0xFF && data[1] == 0xFE)
    {
        text.assign(reinterpret_cast<const wchar_t*>(data.data() + 2), (data.size() - 2) / 2);
        return true;
    }
    size_t skip = data.size() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF ? 3 : 0;
    const char* src = reinterpret_cast<const char*>(data.data() + skip);
    int len = static_cast<int>(data.size() - skip);
    UINT codePage = CP_UTF8;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, len, nullptr, 0);
    if (n == 0 && len > 0)
    {
        codePage = CP_ACP;
        n = MultiByteToWideChar(CP_ACP, 0, src, len, nullptr, 0);
    }
    text.assign(n, L'\0');
    MultiByteToWideChar(codePage, 0, src, len, text.data(), n);
    return true;
}

// Guesses the algorithm from the digest length (the most common one wins).
bool AlgorithmForLength(size_t hexLength, int& alg)
{
    switch (hexLength)
    {
    case 8:   alg = static_cast<int>(HashAlg::CRC32);  return true;
    case 32:  alg = static_cast<int>(HashAlg::MD5);    return true;
    case 40:  alg = static_cast<int>(HashAlg::SHA1);   return true;
    case 48:  alg = static_cast<int>(HashAlg::TIGER);  return true;
    case 64:  alg = static_cast<int>(HashAlg::SHA256); return true;
    case 96:  alg = static_cast<int>(HashAlg::SHA384); return true;
    case 128: alg = static_cast<int>(HashAlg::SHA512); return true;
    default:  return false;
    }
}

struct CheckEntry
{
    std::wstring display;
    std::wstring path;
    std::wstring expected;
    int alg = 0;
    FileHashResult result;
    bool ok = false;
};

// Parses "<hash> *<path>", "<hash>  <path>" or BSD "ALG (<path>) = <hash>".
bool ParseCheckLine(const std::wstring& line, int defaultAlg, CheckEntry& entry)
{
    size_t open = line.find(L" (");
    size_t close = line.rfind(L") = ");
    int alg = 0;
    if (open != std::wstring::npos && close != std::wstring::npos && close > open &&
        ParseAlgorithm(line.substr(0, open), alg) && IsHex(line.substr(close + 4)))
    {
        entry.alg = alg;
        entry.display = line.substr(open + 2, close - open - 2);
        entry.expected = line.substr(close + 4);
        return true;
    }

    size_t space = line.find(L' ');
    if (space == std::wstring::npos || !IsHex(line.substr(0, space)))
        return false;
    entry.expected = line.substr(0, space);
    std::wstring rest = line.substr(space + 1);
    if (!rest.empty() && (rest[0] == L'*' || rest[0] == L' '))
        rest.erase(0, 1);
    if (rest.empty())
        return false;
    entry.display = rest;
    if (defaultAlg >= 0)
        entry.alg = defaultAlg;
    else if (!AlgorithmForLength(entry.expected.size(), entry.alg))
        return false;
    return true;
}

int RunVerify(CliOptions& opt, Console& con)
{
    std::wstring text;
    if (!ReadTextFile(opt.checkFile, text))
    {
        con.Error(opt.checkFile + L": " + ErrorMessage(GetLastError()));
        return kExitFailed;
    }

    // Algorithm: explicit option, then file extension, then digest length per line.
    int defaultAlg = -1;
    for (int i = 0; i < kHashAlgCount && opt.anyAlgorithm; ++i)
        if (opt.hash.selected[i]) { defaultAlg = i; break; }
    if (defaultAlg < 0)
    {
        std::wstring ext = PathFindExtensionW(opt.checkFile.c_str());
        if (ext.size() > 1)
            ParseAlgorithm(ext.substr(1), defaultAlg) || (defaultAlg = -1);
    }

    std::wstring base = opt.checkFile;
    size_t slash = base.find_last_of(L"\\/");
    base = slash == std::wstring::npos ? L"" : base.substr(0, slash + 1);

    std::vector<CheckEntry> entries;
    size_t malformed = 0;
    for (std::wstring line : Split(text, L"\n"))
    {
        while (!line.empty() && (line.back() == L'\r' || line.back() == L' ' || line.back() == L'\t'))
            line.pop_back();
        if (line.empty() || line[0] == L';' || line[0] == L'#')
            continue;
        CheckEntry entry;
        if (!ParseCheckLine(line, defaultAlg, entry))
        {
            ++malformed;
            continue;
        }
        entry.path = entry.display;
        std::replace(entry.path.begin(), entry.path.end(), L'/', L'\\');
        // Relative paths: current folder first (like sha256sum -c), then the
        // checksum file's folder, so "HashCalc -c D:\x\files.sha256" works too.
        if (PathIsRelativeW(entry.path.c_str()) &&
            GetFileAttributesW(LongPath(entry.path).c_str()) == INVALID_FILE_ATTRIBUTES &&
            GetFileAttributesW(LongPath(base + entry.path).c_str()) != INVALID_FILE_ATTRIBUTES)
            entry.path = base + entry.path;
        entries.push_back(std::move(entry));
    }
    if (entries.empty())
    {
        con.Error(opt.checkFile + L": no properly formatted checksum lines found");
        return kExitFailed;
    }

    if (opt.banner)
        con.Out(kBanner);

    size_t passed = 0, mismatched = 0, unreadable = 0;
    auto work = [&](size_t i, std::vector<BYTE>& buffer) {
        CheckEntry& e = entries[i];
        HashOptions options;
        options.selected[e.alg] = true;
        options.hmac = opt.hash.hmac;
        options.key = opt.hash.key;
        e.ok = HashFile(e.path, options, e.result, buffer);
    };
    auto print = [&](size_t i) {
        CheckEntry& e = entries[i];
        if (!e.ok)
        {
            ++unreadable;
            con.Out(e.display + L": FAILED open or read (" + e.result.error + L")\n");
        }
        else if (_wcsicmp(e.result.hashes[e.alg].c_str(), e.expected.c_str()) == 0)
        {
            ++passed;
            con.Out(e.display + L": OK\n");
        }
        else
        {
            ++mismatched;
            con.Out(e.display + L": FAILED\n");
        }
        e = CheckEntry();
    };
    RunOrdered(entries.size(), DefaultThreads(opt), work, print);

    wchar_t summary[160];
    swprintf_s(summary, L"\n%zu OK, %zu FAILED, %zu unreadable", passed, mismatched, unreadable);
    con.Out(summary);
    if (malformed)
        con.Out(L", " + std::to_wstring(malformed) + L" malformed line(s) skipped");
    con.Out(L"\n");
    return mismatched || unreadable ? kExitFailed : kExitOk;
}

} // namespace

int RunCli(int argc, wchar_t** argv)
{
    Console con;
    CliOptions opt;
    bool showHelp = false;
    if (!ParseArgs(argc, argv, opt, con, showHelp))
        return kExitUsage;

    if (showHelp || (opt.inputs.empty() && opt.texts.empty() && opt.hexes.empty() && opt.checkFile.empty()))
    {
        con.Out(std::wstring(kBanner) + kUsage);
        return showHelp ? kExitOk : kExitUsage;
    }

    if (!opt.outFile.empty() && !con.out.OpenFile(opt.outFile))
    {
        con.Error(opt.outFile + L": " + ErrorMessage(GetLastError()));
        return kExitFailed;
    }

    if (!opt.checkFile.empty())
        return RunVerify(opt, con);

    if (!opt.anyAlgorithm)
        opt.hash.selected[static_cast<int>(HashAlg::SHA256)] = true;
    return RunHash(opt, con);
}

bool IsCliInvocation(int argc, wchar_t** argv)
{
    if (argc < 2)
        return false;
    const wchar_t* first = argv[1];
    if (first[0] == L'-')
        return true;
    return first[0] == L'/' && first[1] != L'\0' && _wcsicmp(first, L"/folder") != 0;
}

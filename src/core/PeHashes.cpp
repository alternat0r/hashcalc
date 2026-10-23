// Hashes of the structure of Windows programs (PE files: .exe, .dll, .sys...):
//   Imphash       MD5 of the imported functions ("dll.function,..."), as pefile
//   Authentihash  SHA256 of the file without its signature (Authenticode)
//   RichHash      MD5 of the decoded "Rich" header that Microsoft linkers add
// The results match pefile / signify, which VirusTotal and most tools use.
//
// The input may be hostile: every read is bounds-checked and every loop has a
// limit, so malformed files give "(...)" messages instead of misbehaving.

#include "core/Hashes.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

constexpr size_t kMaxPeFileSize = 256u << 20;   // PE hashes keep the file in memory

struct OrdinalName
{
    const char* dll;
    unsigned ordinal;
    const char* name;
};

const OrdinalName kOrdinalNames[] = {
#include "core/OrdinalNames.inc"
};

// Bounds-checked little-endian reads from the file bytes.
class Bytes
{
public:
    explicit Bytes(const std::vector<BYTE>& data) : m_data(data) {}

    size_t Size() const { return m_data.size(); }
    bool Has(uint64_t offset, uint64_t length) const
    {
        return offset <= m_data.size() && length <= m_data.size() - offset;
    }
    // Offsets are checked with Has() first, so they fit in size_t.
    uint16_t U16(uint64_t o) const
    {
        if (!Has(o, 2)) return 0;
        const size_t i = static_cast<size_t>(o);
        return uint16_t(m_data[i] | (m_data[i + 1] << 8));
    }
    uint32_t U32(uint64_t o) const { return Has(o, 4) ? uint32_t(U16(o)) | (uint32_t(U16(o + 2)) << 16) : 0; }
    uint64_t U64(uint64_t o) const { return Has(o, 8) ? uint64_t(U32(o)) | (uint64_t(U32(o + 4)) << 32) : 0; }
    const BYTE* At(uint64_t o) const { return m_data.data() + static_cast<size_t>(o); }

    // Zero-terminated ASCII string (at most maxLength bytes, stops at the end of the file).
    std::string String(uint64_t o, size_t maxLength) const
    {
        std::string s;
        if (o >= m_data.size())
            return s;
        for (size_t i = static_cast<size_t>(o); i < m_data.size() && s.size() < maxLength && m_data[i] != 0; ++i)
            s += static_cast<char>(m_data[i]);
        return s;
    }

private:
    const std::vector<BYTE>& m_data;
};

struct Section
{
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawPointer;
    uint32_t rawSize;
};

struct PeImage
{
    uint32_t lfanew = 0;
    uint64_t optionalHeader = 0;   // file offset
    uint16_t optionalHeaderSize = 0;
    bool pe64 = false;
    uint32_t sectionAlignment = 0;
    uint32_t fileAlignment = 0;
    uint32_t dataDirectoryCount = 0;
    uint64_t dataDirectories = 0;   // file offset
    std::vector<Section> sections;
};

bool ParseHeaders(const Bytes& b, PeImage& pe)
{
    if (b.U16(0) != 0x5A4D)   // "MZ"
        return false;
    pe.lfanew = b.U32(0x3C);
    if (!b.Has(pe.lfanew, 24) || b.U32(pe.lfanew) != 0x00004550)   // "PE\0\0"
        return false;
    const uint64_t fileHeader = uint64_t(pe.lfanew) + 4;
    const uint16_t sectionCount = b.U16(fileHeader + 2);
    pe.optionalHeaderSize = b.U16(fileHeader + 16);
    pe.optionalHeader = fileHeader + 20;

    const uint16_t magic = b.U16(pe.optionalHeader);
    if (magic == 0x20B)
        pe.pe64 = true;
    else if (magic != 0x10B)
        return false;
    pe.sectionAlignment = b.U32(pe.optionalHeader + 32);
    pe.fileAlignment = b.U32(pe.optionalHeader + 36);
    pe.dataDirectoryCount = std::min<uint32_t>(16, b.U32(pe.optionalHeader + (pe.pe64 ? 108 : 92)));
    pe.dataDirectories = pe.optionalHeader + (pe.pe64 ? 112 : 96);

    const uint64_t sectionTable = pe.optionalHeader + pe.optionalHeaderSize;
    for (unsigned i = 0; i < sectionCount && i < 0x800; ++i)
    {
        const uint64_t s = sectionTable + uint64_t(i) * 40;
        if (!b.Has(s, 40))
            break;
        pe.sections.push_back({ b.U32(s + 12), b.U32(s + 8), b.U32(s + 20), b.U32(s + 16) });
    }
    return true;
}

// RVA -> file offset, with pefile's alignment rules so the results match it.
uint64_t AdjustFileAlignment(uint64_t value, uint32_t fileAlignment)
{
    return fileAlignment < 0x200 ? value : (value / 0x200) * 0x200;
}

uint64_t AdjustSectionAlignment(uint64_t value, uint32_t sectionAlignment, uint32_t fileAlignment)
{
    if (sectionAlignment < 0x1000)
        sectionAlignment = fileAlignment;
    if (sectionAlignment && value % sectionAlignment)
        return uint64_t(sectionAlignment) * (value / sectionAlignment);
    return value;
}

bool RvaToOffset(const Bytes& b, const PeImage& pe, uint64_t rva, uint64_t& offset)
{
    for (size_t i = 0; i < pe.sections.size(); ++i)
    {
        const Section& s = pe.sections[i];
        const uint64_t raw = AdjustFileAlignment(s.rawPointer, pe.fileAlignment);
        uint64_t size = (b.Size() < raw || b.Size() - raw < s.rawSize) ? s.virtualSize
                                                                        : std::max(s.rawSize, s.virtualSize);
        const uint64_t start = AdjustSectionAlignment(s.virtualAddress, pe.sectionAlignment, pe.fileAlignment);
        if (i + 1 < pe.sections.size())
        {
            const uint64_t next = pe.sections[i + 1].virtualAddress;
            if (next > s.virtualAddress && start + size > next)
                size = next > start ? next - start : 0;
        }
        if (rva >= start && rva < start + size)
        {
            offset = rva - start + raw;
            return true;
        }
    }
    if (rva < b.Size())   // headers or data outside the sections
    {
        offset = rva;
        return true;
    }
    return false;
}

bool DataDirectory(const Bytes& b, const PeImage& pe, unsigned index, uint32_t& rva, uint32_t& size)
{
    if (index >= pe.dataDirectoryCount)
        return false;
    rva = b.U32(pe.dataDirectories + uint64_t(index) * 8);
    size = b.U32(pe.dataDirectories + uint64_t(index) * 8 + 4);
    return rva != 0;
}

std::wstring Md5Hex(const std::string& text)
{
    auto md5 = CreateHasher(HashAlg::MD5, nullptr);
    md5->Update(reinterpret_cast<const BYTE*>(text.data()), text.size());
    return md5->FinishText();
}

std::string Lower(std::string s)
{
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

bool AllCharsIn(const std::string& s, const char* allowed)
{
    for (char c : s)
    {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr(allowed, c);
        if (!ok || c == 0) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Imphash
// ---------------------------------------------------------------------------
std::string OrdinalName(const std::string& dllLower, unsigned ordinal)
{
    for (const auto& entry : kOrdinalNames)
        if (entry.ordinal == ordinal && dllLower == entry.dll)
            return entry.name;
    return "ord" + std::to_string(ordinal);
}

std::wstring Imphash(const Bytes& b, const PeImage& pe)
{
    uint32_t importRva = 0, importSize = 0;
    if (!DataDirectory(b, pe, 1, importRva, importSize))
        return L"(no imports)";

    const uint64_t ordinalFlag = pe.pe64 ? 0x8000000000000000ull : 0x80000000ull;
    const uint64_t addressMask = pe.pe64 ? 0x7FFFFFFFFFFFFFFFull : 0x7FFFFFFFull;
    const unsigned thunkSize = pe.pe64 ? 8 : 4;

    std::string list;
    bool anyDescriptor = false;
    for (unsigned d = 0; d < 0x1000; ++d)   // import descriptors
    {
        uint64_t desc = 0;
        if (!RvaToOffset(b, pe, uint64_t(importRva) + uint64_t(d) * 20, desc) || !b.Has(desc, 20))
            break;
        const uint32_t originalFirstThunk = b.U32(desc);
        const uint32_t nameRva = b.U32(desc + 12);
        const uint32_t firstThunk = b.U32(desc + 16);
        if (std::all_of(b.At(desc), b.At(desc) + 20, [](BYTE x) { return x == 0; }))
            break;

        uint64_t nameOffset = 0;
        std::string dll = RvaToOffset(b, pe, nameRva, nameOffset) ? b.String(nameOffset, 0x200) : "";
        if (dll.empty())
            continue;   // pefile skips descriptors without a DLL name
        if (!AllCharsIn(dll, "!#$%&'()-@^_`{}~+,.;=[]\\/"))
            dll = "*invalid*";
        anyDescriptor = true;
        const std::string dllLower = Lower(dll);
        std::string library = dllLower;
        const size_t dot = library.rfind('.');
        if (dot != std::string::npos)
        {
            const std::string ext = library.substr(dot + 1);
            if (ext == "ocx" || ext == "sys" || ext == "dll")
                library.resize(dot);
        }

        const uint32_t table = originalFirstThunk ? originalFirstThunk : firstThunk;
        for (unsigned t = 0; t < 0x2000; ++t)   // thunks
        {
            uint64_t thunkOffset = 0;
            if (!RvaToOffset(b, pe, uint64_t(table) + uint64_t(t) * thunkSize, thunkOffset) ||
                !b.Has(thunkOffset, thunkSize))
                break;
            const uint64_t thunk = pe.pe64 ? b.U64(thunkOffset) : b.U32(thunkOffset);
            if (thunk == 0)
                break;

            std::string function;
            if (thunk & ordinalFlag)
            {
                function = OrdinalName(dllLower, static_cast<unsigned>(thunk & 0xFFFF));
            }
            else
            {
                uint64_t hintName = 0;
                if (!RvaToOffset(b, pe, (thunk & addressMask) + 2, hintName))
                    continue;
                function = b.String(hintName, 0x200);
                if (!AllCharsIn(function, "._?@$()<>"))
                    function = "*invalid*";
            }
            if (function.empty())
                continue;
            if (!list.empty())
                list += ',';
            list += Lower(library) + "." + Lower(function);
        }
    }
    if (!anyDescriptor)
        return L"(no imports)";
    return Md5Hex(list);
}

// ---------------------------------------------------------------------------
// Rich header hash: MD5 of the header bytes from offset 0x80 up to "Rich",
// decoded with the XOR key stored after "Rich".
// ---------------------------------------------------------------------------
std::wstring RichHash(const std::vector<BYTE>& data, const PeImage& pe)
{
    const uint64_t searchEnd = std::min<uint64_t>(data.size(), uint64_t(pe.lfanew) + 24);
    if (searchEnd < 0x80 + 4)
        return L"(no Rich header)";
    const BYTE rich[] = { 'R', 'i', 'c', 'h' };
    const BYTE* found = std::search(data.data() + 0x80, data.data() + searchEnd, rich, rich + 4);
    if (found == data.data() + searchEnd)
        return L"(no Rich header)";
    const size_t richIndex = static_cast<size_t>(found - data.data());
    if (richIndex + 8 > data.size())
        return L"(no Rich header)";

    // Dwords from 0x80 to just after the key; the key is the dword after "Rich".
    const size_t blockLength = ((richIndex + 8 - 0x80) / 4) * 4;
    const BYTE* block = data.data() + 0x80;
    auto dword = [&](size_t i) { return uint32_t(block[4 * i]) | uint32_t(block[4 * i + 1]) << 8 |
                                        uint32_t(block[4 * i + 2]) << 16 | uint32_t(block[4 * i + 3]) << 24; };
    const size_t dwords = blockLength / 4;
    size_t richDword = dwords;
    for (size_t i = 0; i < dwords; ++i)
        if (dword(i) == 0x68636952) { richDword = i; break; }   // "Rich"
    if (richDword + 1 >= dwords || dwords < 4)
        return L"(no Rich header)";
    const uint32_t key = dword(richDword + 1);
    // The encoded block starts with "DanS" and three copies of the key.
    if ((dword(0) ^ dword(1)) != 0x536E6144 || dword(2) != dword(1) || dword(3) != dword(1))
        return L"(no Rich header)";

    std::string clear(richIndex - 0x80, '\0');
    for (size_t i = 0; i < clear.size(); ++i)
        clear[i] = static_cast<char>(block[i] ^ static_cast<BYTE>(key >> (8 * (i % 4))));
    return Md5Hex(clear);
}

// ---------------------------------------------------------------------------
// Authentihash: SHA256 of the file except the checksum, the certificate entry
// of the data directory and the certificate table (Authenticode, as signify).
// ---------------------------------------------------------------------------
std::wstring Authentihash(const Bytes& b, const PeImage& pe)
{
    struct Range { uint64_t start, length; };
    std::vector<Range> omit = { { pe.optionalHeader + 64, 4 } };   // CheckSum

    const uint64_t optionalEnd = pe.optionalHeader + pe.optionalHeaderSize;
    const uint64_t rvaCountField = pe.optionalHeader + (pe.pe64 ? 108 : 92);
    const uint64_t certEntry = pe.optionalHeader + (pe.pe64 ? 144 : 128);
    if (optionalEnd >= rvaCountField + 4 && b.U32(rvaCountField) >= 5 && optionalEnd >= certEntry + 8)
    {
        omit.push_back({ certEntry, 8 });
        const uint32_t address = b.U32(certEntry);
        const uint32_t size = b.U32(certEntry + 4);
        if (size && address >= optionalEnd && uint64_t(address) + size <= b.Size())
            omit.push_back({ address, size });
    }
    std::sort(omit.begin(), omit.end(), [](const Range& x, const Range& y) { return x.start < y.start; });

    auto sha = CreateHasher(HashAlg::SHA256, nullptr);
    uint64_t position = 0;
    for (const Range& r : omit)
    {
        const uint64_t end = std::min<uint64_t>(r.start, b.Size());
        if (end > position)
            sha->Update(b.At(position), static_cast<size_t>(end - position));
        position = std::max(position, std::min<uint64_t>(r.start + r.length, b.Size()));
    }
    if (position < b.Size())
        sha->Update(b.At(position), static_cast<size_t>(b.Size() - position));
    return sha->FinishText();
}

// Keeps the file in memory (PE files are small); gives up early on files that
// are not PE files or are too large.
class PeHasher : public Hasher
{
public:
    explicit PeHasher(HashAlg alg) : m_alg(alg) {}

    void Update(const BYTE* data, size_t len) override
    {
        if (m_state != State::Collecting)
            return;
        if (m_data.size() + len > kMaxPeFileSize)
        {
            m_state = State::TooLarge;
            std::vector<BYTE>().swap(m_data);
            return;
        }
        m_data.insert(m_data.end(), data, data + len);
        if (m_data.size() >= 2 && (m_data[0] != 'M' || m_data[1] != 'Z'))
        {
            m_state = State::NotPe;
            std::vector<BYTE>().swap(m_data);
        }
    }

    std::vector<BYTE> Finish() override { return {}; }   // text result only

    std::wstring FinishText() override
    {
        if (m_state == State::TooLarge)
            return L"(file too large for PE hashes)";
        PeImage pe;
        Bytes bytes(m_data);
        if (m_state == State::NotPe || !ParseHeaders(bytes, pe))
            return L"(not a Windows program)";
        switch (m_alg)
        {
        case HashAlg::IMPHASH:      return Imphash(bytes, pe);
        case HashAlg::RICHHASH:     return RichHash(m_data, pe);
        case HashAlg::AUTHENTIHASH: return Authentihash(bytes, pe);
        default:                    return L"";
        }
    }

private:
    enum class State { Collecting, NotPe, TooLarge };
    HashAlg m_alg;
    State m_state = State::Collecting;
    std::vector<BYTE> m_data;
};

} // namespace

std::unique_ptr<Hasher> CreatePeHasher(HashAlg alg)
{
    return std::make_unique<PeHasher>(alg);
}

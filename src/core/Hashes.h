#pragma once

#include <windows.h>
#include <memory>
#include <string>
#include <vector>

// The order is kept stable: it is the bit position in the saved settings and
// the offset of each algorithm's controls (IDC_CHK_BASE + index).
enum class HashAlg
{
    MD5, MD4, SHA1, SHA256, SHA384, SHA512,
    RIPEMD160, PANAMA, TIGER, MD2, ADLER32, CRC32,
    EDONKEY,
    // PE and similarity hashes (View > PE & Similarity Hashes)
    IMPHASH, AUTHENTIHASH, RICHHASH, SSDEEP, TLSH,
    Count
};

constexpr int kHashAlgCount = static_cast<int>(HashAlg::Count);

// Display name, e.g. L"SHA256".
const wchar_t* HashAlgName(HashAlg alg);

// The PE (Windows program) and similarity hashes, shown only when enabled.
bool IsExtendedHash(HashAlg alg);

// Algorithm selection and optional HMAC key for a hash run.
struct HashOptions
{
    bool selected[kHashAlgCount] = {};
    bool hmac = false;
    std::vector<BYTE> key;

    const std::vector<BYTE>* Key() const { return hmac ? &key : nullptr; }
};

class Hasher
{
public:
    virtual ~Hasher() = default;
    virtual void Update(const BYTE* data, size_t len) = 0;
    virtual std::vector<BYTE> Finish() = 0;

    // The result as shown to the user: lowercase hex for digests; the native
    // text form for ssdeep/TLSH; a "(...)" message when there is no result
    // (e.g. Imphash of a file that is not a Windows program).
    virtual std::wstring FinishText();
};

// Returns true if the algorithm has an implementation.
bool IsImplemented(HashAlg alg);

// Returns true if the algorithm can be used as HMAC.
bool SupportsHmac(HashAlg alg);

// Creates a hasher, or nullptr if not implemented / HMAC unsupported.
// hmacKey == nullptr means a plain hash. Throws std::runtime_error on CNG failure.
std::unique_ptr<Hasher> CreateHasher(HashAlg alg, const std::vector<BYTE>* hmacKey);

std::wstring ToHex(const std::vector<BYTE>& bytes);

// Parses hex digits, ignoring whitespace. Returns false on invalid input.
bool ParseHex(const std::wstring& text, std::vector<BYTE>& out);

// Implemented in PeHashes.cpp and FuzzyHashes.cpp.
std::unique_ptr<Hasher> CreatePeHasher(HashAlg alg);
std::unique_ptr<Hasher> CreateSsdeepHasher();
std::unique_ptr<Hasher> CreateTlshHasher();

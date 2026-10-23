#pragma once

#include <windows.h>
#include <memory>
#include <string>
#include <vector>

// Order matches the rows in the dialog (IDC_CHK_BASE + index / IDC_OUT_BASE + index).
enum class HashAlg
{
    MD5, MD4, SHA1, SHA256, SHA384, SHA512,
    RIPEMD160, PANAMA, TIGER, MD2, ADLER32, CRC32,
    EDONKEY,
    Count
};

constexpr int kHashAlgCount = static_cast<int>(HashAlg::Count);

// Display name, e.g. L"SHA256".
const wchar_t* HashAlgName(HashAlg alg);

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

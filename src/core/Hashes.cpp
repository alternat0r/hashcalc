#include "core/Hashes.h"

#include <bcrypt.h>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace {

// ---------------------------------------------------------------------------
// Windows CNG (BCrypt) based hash / HMAC
// ---------------------------------------------------------------------------
class CngHasher : public Hasher
{
public:
    CngHasher(LPCWSTR algId, const std::vector<BYTE>* hmacKey)
    {
        ULONG flags = hmacKey ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&m_alg, algId, nullptr, flags)))
            throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        DWORD cb = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(m_alg, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&m_hashLen), sizeof(m_hashLen), &cb, 0)))
            throw std::runtime_error("BCryptGetProperty failed");

        PUCHAR key = nullptr;
        ULONG keyLen = 0;
        if (hmacKey && !hmacKey->empty())
        {
            key = const_cast<PUCHAR>(hmacKey->data());
            keyLen = static_cast<ULONG>(hmacKey->size());
        }
        if (!BCRYPT_SUCCESS(BCryptCreateHash(m_alg, &m_hash, nullptr, 0, key, keyLen, 0)))
            throw std::runtime_error("BCryptCreateHash failed");
    }

    ~CngHasher() override
    {
        if (m_hash) BCryptDestroyHash(m_hash);
        if (m_alg) BCryptCloseAlgorithmProvider(m_alg, 0);
    }

    CngHasher(const CngHasher&) = delete;
    CngHasher& operator=(const CngHasher&) = delete;

    void Update(const BYTE* data, size_t len) override
    {
        while (len > 0)
        {
            ULONG part = len > 0x40000000 ? 0x40000000 : static_cast<ULONG>(len);
            if (!BCRYPT_SUCCESS(BCryptHashData(m_hash, const_cast<PUCHAR>(data), part, 0)))
                throw std::runtime_error("BCryptHashData failed");
            data += part;
            len -= part;
        }
    }

    std::vector<BYTE> Finish() override
    {
        std::vector<BYTE> digest(m_hashLen);
        if (!BCRYPT_SUCCESS(BCryptFinishHash(m_hash, digest.data(), m_hashLen, 0)))
            throw std::runtime_error("BCryptFinishHash failed");
        return digest;
    }

private:
    BCRYPT_ALG_HANDLE m_alg = nullptr;
    BCRYPT_HASH_HANDLE m_hash = nullptr;
    DWORD m_hashLen = 0;
};

// ---------------------------------------------------------------------------
// CRC32 (IEEE 802.3, reflected polynomial 0xEDB88320)
// ---------------------------------------------------------------------------
class Crc32Hasher : public Hasher
{
public:
    Crc32Hasher()
    {
        for (DWORD i = 0; i < 256; ++i)
        {
            DWORD c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            m_table[i] = c;
        }
    }

    void Update(const BYTE* data, size_t len) override
    {
        for (size_t i = 0; i < len; ++i)
            m_crc = m_table[(m_crc ^ data[i]) & 0xFF] ^ (m_crc >> 8);
    }

    std::vector<BYTE> Finish() override
    {
        DWORD v = m_crc ^ 0xFFFFFFFFu;
        return { BYTE(v >> 24), BYTE(v >> 16), BYTE(v >> 8), BYTE(v) };
    }

private:
    DWORD m_table[256];
    DWORD m_crc = 0xFFFFFFFFu;
};

// ---------------------------------------------------------------------------
// Adler-32
// ---------------------------------------------------------------------------
class Adler32Hasher : public Hasher
{
public:
    void Update(const BYTE* data, size_t len) override
    {
        constexpr DWORD kMod = 65521;
        while (len > 0)
        {
            // 5552 is the largest n such that sums cannot overflow 32 bits.
            size_t n = len < 5552 ? len : 5552;
            len -= n;
            while (n--)
            {
                m_a += *data++;
                m_b += m_a;
            }
            m_a %= kMod;
            m_b %= kMod;
        }
    }

    std::vector<BYTE> Finish() override
    {
        DWORD v = (m_b << 16) | m_a;
        return { BYTE(v >> 24), BYTE(v >> 16), BYTE(v >> 8), BYTE(v) };
    }

private:
    DWORD m_a = 1;
    DWORD m_b = 0;
};

// ---------------------------------------------------------------------------
// eDonkey / eMule (ed2k): MD4 over 9,728,000-byte chunks. A single-chunk input
// yields that chunk's MD4; otherwise the MD4 of the concatenated chunk digests.
// ---------------------------------------------------------------------------
class EDonkeyHasher : public Hasher
{
public:
    EDonkeyHasher() : m_chunk(std::make_unique<CngHasher>(BCRYPT_MD4_ALGORITHM, nullptr)) {}

    void Update(const BYTE* data, size_t len) override
    {
        while (len > 0)
        {
            size_t take = kChunkSize - m_inChunk;
            if (take > len) take = len;
            m_chunk->Update(data, take);
            m_inChunk += take;
            data += take;
            len -= take;

            if (m_inChunk == kChunkSize)
                CloseChunk();
        }
    }

    std::vector<BYTE> Finish() override
    {
        if (m_inChunk > 0 || m_chunkCount == 0)
            CloseChunk();

        if (m_chunkCount == 1)
            return m_digests;

        CngHasher root(BCRYPT_MD4_ALGORITHM, nullptr);
        root.Update(m_digests.data(), m_digests.size());
        return root.Finish();
    }

private:
    void CloseChunk()
    {
        std::vector<BYTE> d = m_chunk->Finish();
        m_digests.insert(m_digests.end(), d.begin(), d.end());
        ++m_chunkCount;
        m_inChunk = 0;
        m_chunk = std::make_unique<CngHasher>(BCRYPT_MD4_ALGORITHM, nullptr);
    }

    static constexpr size_t kChunkSize = 9728000;
    std::unique_ptr<CngHasher> m_chunk;
    std::vector<BYTE> m_digests;
    size_t m_inChunk = 0;
    size_t m_chunkCount = 0;
};

// ---------------------------------------------------------------------------
// Helpers for the hand-written (non-CNG) block hashes
// ---------------------------------------------------------------------------
inline uint32_t Rotl32(uint32_t x, unsigned n) { n &= 31; return n ? (x << n) | (x >> (32 - n)) : x; }

inline uint32_t LoadLE32(const BYTE* p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

inline uint64_t LoadLE64(const BYTE* p)
{
    return uint64_t(LoadLE32(p)) | (uint64_t(LoadLE32(p + 4)) << 32);
}

inline void StoreLE32(std::vector<BYTE>& out, uint32_t v)
{
    for (int i = 0; i < 4; ++i) out.push_back(BYTE(v >> (8 * i)));
}

inline void StoreLE64(std::vector<BYTE>& out, uint64_t v)
{
    for (int i = 0; i < 8; ++i) out.push_back(BYTE(v >> (8 * i)));
}

// Splits input into fixed-size blocks and provides MD-style padding.
template <size_t BlockSize>
class BlockHasher : public Hasher
{
public:
    void Update(const BYTE* data, size_t len) override
    {
        m_total += len;
        if (m_used > 0)
        {
            size_t take = BlockSize - m_used;
            if (take > len) take = len;
            memcpy(m_buf + m_used, data, take);
            m_used += take;
            data += take;
            len -= take;
            if (m_used < BlockSize)
                return;
            ProcessBlock(m_buf);
            m_used = 0;
        }
        for (; len >= BlockSize; data += BlockSize, len -= BlockSize)
            ProcessBlock(data);
        memcpy(m_buf, data, len);
        m_used = len;
    }

protected:
    virtual void ProcessBlock(const BYTE* block) = 0;

    // Appends padByte and zeros up to the block boundary, optionally ending
    // with the message length in bits as a 64-bit little-endian value.
    void Pad(BYTE padByte, bool appendBitLength)
    {
        const size_t lenBytes = appendBitLength ? 8 : 0;
        const uint64_t bits = uint64_t(m_total) * 8;

        m_buf[m_used++] = padByte;
        if (m_used > BlockSize - lenBytes)
        {
            memset(m_buf + m_used, 0, BlockSize - m_used);
            ProcessBlock(m_buf);
            m_used = 0;
        }
        memset(m_buf + m_used, 0, BlockSize - m_used);
        if (appendBitLength)
            for (int i = 0; i < 8; ++i)
                m_buf[BlockSize - 8 + i] = BYTE(bits >> (8 * i));
        ProcessBlock(m_buf);
        m_used = 0;
    }

    // Bytes waiting for the block to fill up (0 .. BlockSize-1).
    size_t BufferedBytes() const { return m_used; }

private:
    BYTE m_buf[BlockSize] = {};
    size_t m_used = 0;
    uint64_t m_total = 0;
};

// ---------------------------------------------------------------------------
// RIPEMD-160 (Dobbertin, Bosselaers, Preneel)
// ---------------------------------------------------------------------------
class Ripemd160Hasher : public BlockHasher<64>
{
public:
    std::vector<BYTE> Finish() override
    {
        Pad(0x80, true);
        std::vector<BYTE> out;
        for (uint32_t v : m_h)
            StoreLE32(out, v);
        return out;
    }

protected:
    void ProcessBlock(const BYTE* block) override
    {
        static const BYTE kRL[80] = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 };
        static const BYTE kRR[80] = {
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 };
        static const BYTE kSL[80] = {
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 };
        static const BYTE kSR[80] = {
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 };
        static const uint32_t kKL[5] = { 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
        static const uint32_t kKR[5] = { 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

        auto f = [](int j, uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
            switch (j / 16)
            {
            case 0:  return x ^ y ^ z;
            case 1:  return (x & y) | (~x & z);
            case 2:  return (x | ~y) ^ z;
            case 3:  return (x & z) | (y & ~z);
            default: return x ^ (y | ~z);
            }
        };

        uint32_t x[16];
        for (int i = 0; i < 16; ++i)
            x[i] = LoadLE32(block + 4 * i);

        uint32_t al = m_h[0], bl = m_h[1], cl = m_h[2], dl = m_h[3], el = m_h[4];
        uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;
        for (int j = 0; j < 80; ++j)
        {
            uint32_t t = Rotl32(al + f(j, bl, cl, dl) + x[kRL[j]] + kKL[j / 16], kSL[j]) + el;
            al = el; el = dl; dl = Rotl32(cl, 10); cl = bl; bl = t;

            t = Rotl32(ar + f(79 - j, br, cr, dr) + x[kRR[j]] + kKR[j / 16], kSR[j]) + er;
            ar = er; er = dr; dr = Rotl32(cr, 10); cr = br; br = t;
        }

        uint32_t t = m_h[1] + cl + dr;
        m_h[1] = m_h[2] + dl + er;
        m_h[2] = m_h[3] + el + ar;
        m_h[3] = m_h[4] + al + br;
        m_h[4] = m_h[0] + bl + cr;
        m_h[0] = t;
    }

private:
    uint32_t m_h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
};

// ---------------------------------------------------------------------------
// Tiger/192 (Anderson, Biham). The S-boxes are generated at first use with
// the procedure published by the authors instead of embedding 8 KB of tables.
// ---------------------------------------------------------------------------
void TigerCompress(const uint64_t* sbox, const uint64_t block[8], uint64_t state[3])
{
    const uint64_t* t1 = sbox;
    const uint64_t* t2 = sbox + 256;
    const uint64_t* t3 = sbox + 512;
    const uint64_t* t4 = sbox + 768;

    uint64_t x[8];
    memcpy(x, block, sizeof(x));
    uint64_t a = state[0], b = state[1], c = state[2];

    auto round = [&](uint64_t& ra, uint64_t& rb, uint64_t& rc, uint64_t xi, uint64_t mul) {
        rc ^= xi;
        ra -= t1[BYTE(rc)] ^ t2[BYTE(rc >> 16)] ^ t3[BYTE(rc >> 32)] ^ t4[BYTE(rc >> 48)];
        rb += t4[BYTE(rc >> 8)] ^ t3[BYTE(rc >> 24)] ^ t2[BYTE(rc >> 40)] ^ t1[BYTE(rc >> 56)];
        rb *= mul;
    };
    auto pass = [&](uint64_t& pa, uint64_t& pb, uint64_t& pc, uint64_t mul) {
        round(pa, pb, pc, x[0], mul);
        round(pb, pc, pa, x[1], mul);
        round(pc, pa, pb, x[2], mul);
        round(pa, pb, pc, x[3], mul);
        round(pb, pc, pa, x[4], mul);
        round(pc, pa, pb, x[5], mul);
        round(pa, pb, pc, x[6], mul);
        round(pb, pc, pa, x[7], mul);
    };
    auto keySchedule = [&]() {
        x[0] -= x[7] ^ 0xA5A5A5A5A5A5A5A5ull;
        x[1] ^= x[0];
        x[2] += x[1];
        x[3] -= x[2] ^ ((~x[1]) << 19);
        x[4] ^= x[3];
        x[5] += x[4];
        x[6] -= x[5] ^ ((~x[4]) >> 23);
        x[7] ^= x[6];
        x[0] += x[7];
        x[1] -= x[0] ^ ((~x[7]) << 19);
        x[2] ^= x[1];
        x[3] += x[2];
        x[4] -= x[3] ^ ((~x[2]) >> 23);
        x[5] ^= x[4];
        x[6] += x[5];
        x[7] -= x[6] ^ 0x0123456789ABCDEFull;
    };

    const uint64_t aa = a, bb = b, cc = c;
    pass(a, b, c, 5);
    keySchedule();
    pass(c, a, b, 7);
    keySchedule();
    pass(b, c, a, 9);

    state[0] = a ^ aa;
    state[1] = b - bb;
    state[2] = c + cc;
}

const uint64_t kTigerInit[3] = { 0x0123456789ABCDEFull, 0xFEDCBA9876543210ull, 0xF096A5B4C3B2E187ull };

struct TigerSboxes
{
    uint64_t table[4 * 256];

    TigerSboxes()
    {
        static const char kSeed[] = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham";
        static_assert(sizeof(kSeed) == 65, "seed must be one 64-byte block");

        uint64_t block[8];
        for (int i = 0; i < 8; ++i)
            block[i] = LoadLE64(reinterpret_cast<const BYTE*>(kSeed) + 8 * i);

        auto byteOf = [](uint64_t v, int i) { return BYTE(v >> (8 * i)); };
        auto setByte = [](uint64_t& v, int i, BYTE b) {
            v = (v & ~(uint64_t(0xFF) << (8 * i))) | (uint64_t(b) << (8 * i));
        };

        for (int i = 0; i < 1024; ++i)
            table[i] = 0x0101010101010101ull * BYTE(i);

        uint64_t state[3] = { kTigerInit[0], kTigerInit[1], kTigerInit[2] };
        int abc = 2;
        for (int pass = 0; pass < 5; ++pass)
            for (int i = 0; i < 256; ++i)
                for (int sb = 0; sb < 1024; sb += 256)
                {
                    if (++abc == 3)
                    {
                        abc = 0;
                        TigerCompress(table, block, state);
                    }
                    for (int col = 0; col < 8; ++col)
                    {
                        uint64_t& p = table[sb + i];
                        uint64_t& q = table[sb + byteOf(state[abc], col)];
                        BYTE tmp = byteOf(p, col);
                        setByte(p, col, byteOf(q, col));
                        setByte(q, col, tmp);
                    }
                }
    }
};

const uint64_t* TigerTable()
{
    static const TigerSboxes sboxes; // thread-safe one-time generation
    return sboxes.table;
}

class TigerHasher : public BlockHasher<64>
{
public:
    std::vector<BYTE> Finish() override
    {
        Pad(0x01, true); // original Tiger padding (Tiger2 uses 0x80)
        std::vector<BYTE> out;
        for (uint64_t v : m_state)
            StoreLE64(out, v);
        return out;
    }

protected:
    void ProcessBlock(const BYTE* block) override
    {
        uint64_t x[8];
        for (int i = 0; i < 8; ++i)
            x[i] = LoadLE64(block + 8 * i);
        TigerCompress(m_sbox, x, m_state);
    }

private:
    const uint64_t* m_sbox = TigerTable();
    uint64_t m_state[3] = { kTigerInit[0], kTigerInit[1], kTigerInit[2] };
};

// ---------------------------------------------------------------------------
// MD2 (RFC 1319). Slow by design: each 16-byte block runs 18 rounds of 48
// table lookups, and every lookup needs the result of the one before it, so
// the CPU cannot overlap them. Kept as tight as possible: the running value
// stays in a register, the loops are fixed-size so the compiler unrolls them,
// and the checksum (a separate chain) can run alongside the main one.
// ---------------------------------------------------------------------------
const BYTE kMd2Table[256] = {   // permutation built from the digits of pi
     41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
     98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
     30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
    190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
    169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
    128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
    255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
     79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
     69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
     27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
     85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
     44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
    106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
    120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
    242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
     49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20,
};

class Md2Hasher : public BlockHasher<16>
{
public:
    std::vector<BYTE> Finish() override
    {
        // Pad with n bytes of value n (1..16), then hash the checksum block.
        BYTE n = static_cast<BYTE>(16 - BufferedBytes());
        BYTE padding[16];
        memset(padding, n, n);
        Update(padding, n);
        Compress(m_checksum);
        return std::vector<BYTE>(m_state, m_state + 16);
    }

protected:
    void ProcessBlock(const BYTE* block) override
    {
        BYTE last = m_checksum[15];
        for (int j = 0; j < 16; ++j)
            last = m_checksum[j] ^= kMd2Table[block[j] ^ last];
        Compress(block);
    }

private:
    // The table widened to 32 bits: each step of the dependency chain is then a
    // plain load + XOR, with no extra zero-extension of a byte in between.
    static const uint32_t* Table32()
    {
        static const struct Wide
        {
            uint32_t v[256];
            Wide() { for (int i = 0; i < 256; ++i) v[i] = kMd2Table[i]; }
        } wide;
        return wide.v;
    }

    void Compress(const BYTE* block)
    {
        const uint32_t* s = m_table;
        uint32_t x[48];
        for (int j = 0; j < 16; ++j)
        {
            x[j] = m_state[j];
            x[16 + j] = block[j];
            x[32 + j] = static_cast<uint32_t>(m_state[j] ^ block[j]);
        }
        uint32_t t = 0;
        for (uint32_t round = 0; round < 18; ++round)
        {
            // 48 steps written out: no loop counter between the dependent lookups.
#define MD2_STEP(k) t = x[k] ^= s[t];
#define MD2_STEP8(k) MD2_STEP(k) MD2_STEP(k + 1) MD2_STEP(k + 2) MD2_STEP(k + 3) \
                     MD2_STEP(k + 4) MD2_STEP(k + 5) MD2_STEP(k + 6) MD2_STEP(k + 7)
            MD2_STEP8(0) MD2_STEP8(8) MD2_STEP8(16) MD2_STEP8(24) MD2_STEP8(32) MD2_STEP8(40)
#undef MD2_STEP8
#undef MD2_STEP
            t = (t + round) & 0xFF;
        }
        for (int j = 0; j < 16; ++j)
            m_state[j] = static_cast<BYTE>(x[j]);
    }

    const uint32_t* m_table = Table32();

    BYTE m_state[16] = {};
    BYTE m_checksum[16] = {};
};

// ---------------------------------------------------------------------------
// PANAMA hash (Daemen, Clapp): 17-word state and a 32-stage LFSR buffer.
// ---------------------------------------------------------------------------
class PanamaHasher : public BlockHasher<32>
{
public:
    std::vector<BYTE> Finish() override
    {
        Pad(0x01, false);
        for (int i = 0; i < 32; ++i)
            Step(nullptr); // blank pulls
        std::vector<BYTE> out;
        for (int i = 9; i < 17; ++i)
            StoreLE32(out, m_a[i]);
        return out;
    }

protected:
    void ProcessBlock(const BYTE* block) override
    {
        uint32_t p[8];
        for (int i = 0; i < 8; ++i)
            p[i] = LoadLE32(block + 4 * i);
        Step(p);
    }

private:
    uint32_t* Stage(int j) { return m_b[(m_tap + j) & 31]; }

    // One push (input != nullptr) or pull (input == nullptr) iteration.
    void Step(const uint32_t* input)
    {
        uint32_t q[8], sigma1[8], sigma2[8], old31[8];
        for (int i = 0; i < 8; ++i)
        {
            q[i] = input ? input[i] : m_a[i + 1];
            sigma1[i] = input ? input[i] : Stage(4)[i];
            sigma2[i] = Stage(16)[i];
            old31[i] = Stage(31)[i];
        }

        // Buffer update (lambda): shift all stages by one, then feed back.
        m_tap = (m_tap + 31) & 31;
        uint32_t* b0 = Stage(0);
        uint32_t* b25 = Stage(25);
        for (int i = 0; i < 8; ++i)
        {
            b0[i] = old31[i] ^ q[i];
            b25[i] ^= old31[(i + 2) & 7];
        }

        // State update (rho = sigma . theta . pi . gamma)
        uint32_t c[17], d[17];
        for (int i = 0; i < 17; ++i)
            c[i] = m_a[i] ^ (m_a[(i + 1) % 17] | ~m_a[(i + 2) % 17]);
        for (int i = 0; i < 17; ++i)
            d[i] = Rotl32(c[(7 * i) % 17], (i * (i + 1) / 2) % 32);
        for (int i = 0; i < 17; ++i)
            m_a[i] = d[i] ^ d[(i + 1) % 17] ^ d[(i + 4) % 17];

        m_a[0] ^= 1;
        for (int i = 0; i < 8; ++i)
        {
            m_a[i + 1] ^= sigma1[i];
            m_a[i + 9] ^= sigma2[i];
        }
    }

    uint32_t m_a[17] = {};
    uint32_t m_b[32][8] = {};
    int m_tap = 0;
};

// ---------------------------------------------------------------------------
// Generic HMAC (RFC 2104) for the hand-written hashes
// ---------------------------------------------------------------------------
using HasherFactory = std::unique_ptr<Hasher> (*)();

class HmacHasher : public Hasher
{
public:
    HmacHasher(HasherFactory factory, size_t blockSize, const std::vector<BYTE>& key)
        : m_factory(factory), m_inner(factory())
    {
        std::vector<BYTE> k = key;
        if (k.size() > blockSize)
        {
            auto h = factory();
            h->Update(k.data(), k.size());
            k = h->Finish();
        }
        k.resize(blockSize, 0);

        std::vector<BYTE> ipad(blockSize);
        m_opad.resize(blockSize);
        for (size_t i = 0; i < blockSize; ++i)
        {
            ipad[i] = k[i] ^ 0x36;
            m_opad[i] = k[i] ^ 0x5C;
        }
        m_inner->Update(ipad.data(), ipad.size());
    }

    void Update(const BYTE* data, size_t len) override { m_inner->Update(data, len); }

    std::vector<BYTE> Finish() override
    {
        std::vector<BYTE> innerDigest = m_inner->Finish();
        auto outer = m_factory();
        outer->Update(m_opad.data(), m_opad.size());
        outer->Update(innerDigest.data(), innerDigest.size());
        return outer->Finish();
    }

private:
    HasherFactory m_factory;
    std::unique_ptr<Hasher> m_inner;
    std::vector<BYTE> m_opad;
};

template <class T>
std::unique_ptr<Hasher> Make() { return std::make_unique<T>(); }

LPCWSTR CngAlgId(HashAlg alg)
{
    switch (alg)
    {
    case HashAlg::MD5:    return BCRYPT_MD5_ALGORITHM;
    case HashAlg::MD4:    return BCRYPT_MD4_ALGORITHM;
    case HashAlg::SHA1:   return BCRYPT_SHA1_ALGORITHM;
    case HashAlg::SHA256: return BCRYPT_SHA256_ALGORITHM;
    case HashAlg::SHA384: return BCRYPT_SHA384_ALGORITHM;
    case HashAlg::SHA512: return BCRYPT_SHA512_ALGORITHM;
    default:              return nullptr;
    }
}

} // namespace

const wchar_t* HashAlgName(HashAlg alg)
{
    static const wchar_t* const kNames[kHashAlgCount] = {
        L"MD5", L"MD4", L"SHA1", L"SHA256", L"SHA384", L"SHA512",
        L"RIPEMD160", L"PANAMA", L"TIGER", L"MD2", L"ADLER32", L"CRC32",
        L"eDonkey",
        L"Imphash", L"Authentihash", L"RichHash", L"ssdeep", L"TLSH" };
    int i = static_cast<int>(alg);
    return i >= 0 && i < kHashAlgCount ? kNames[i] : L"";
}

bool IsExtendedHash(HashAlg alg)
{
    return alg >= HashAlg::IMPHASH && alg < HashAlg::Count;
}

std::wstring Hasher::FinishText()
{
    return ToHex(Finish());
}

bool IsImplemented(HashAlg /*alg*/)
{
    return true;
}

bool SupportsHmac(HashAlg alg)
{
    switch (alg)
    {
    case HashAlg::ADLER32:
    case HashAlg::CRC32:
    case HashAlg::EDONKEY:
        return false;
    default:
        return !IsExtendedHash(alg);   // structure/similarity hashes have no keyed form
    }
}

std::unique_ptr<Hasher> CreateHasher(HashAlg alg, const std::vector<BYTE>* hmacKey)
{
    if (!IsImplemented(alg) || (hmacKey && !SupportsHmac(alg)))
        return nullptr;

    if (LPCWSTR id = CngAlgId(alg))
        return std::make_unique<CngHasher>(id, hmacKey);

    HasherFactory factory = nullptr;
    size_t blockSize = 64;
    switch (alg)
    {
    case HashAlg::RIPEMD160: factory = Make<Ripemd160Hasher>; break;
    case HashAlg::TIGER:     factory = Make<TigerHasher>; break;
    case HashAlg::PANAMA:    factory = Make<PanamaHasher>; blockSize = 32; break;
    case HashAlg::MD2:       factory = Make<Md2Hasher>; blockSize = 16; break;
    default: break;
    }
    if (factory)
    {
        if (hmacKey)
            return std::make_unique<HmacHasher>(factory, blockSize, *hmacKey);
        return factory();
    }

    switch (alg)
    {
    case HashAlg::CRC32:   return std::make_unique<Crc32Hasher>();
    case HashAlg::ADLER32: return std::make_unique<Adler32Hasher>();
    case HashAlg::EDONKEY: return std::make_unique<EDonkeyHasher>();
    case HashAlg::IMPHASH:
    case HashAlg::AUTHENTIHASH:
    case HashAlg::RICHHASH: return CreatePeHasher(alg);
    case HashAlg::SSDEEP:  return CreateSsdeepHasher();
    case HashAlg::TLSH:    return CreateTlshHasher();
    default:               return nullptr;
    }
}

std::wstring ToHex(const std::vector<BYTE>& bytes)
{
    static const wchar_t kDigits[] = L"0123456789abcdef";
    std::wstring s;
    s.reserve(bytes.size() * 2);
    for (BYTE b : bytes)
    {
        s.push_back(kDigits[b >> 4]);
        s.push_back(kDigits[b & 0x0F]);
    }
    return s;
}

bool ParseHex(const std::wstring& text, std::vector<BYTE>& out)
{
    out.clear();
    int high = -1;
    for (wchar_t c : text)
    {
        int v;
        if (c >= L'0' && c <= L'9')      v = c - L'0';
        else if (c >= L'a' && c <= L'f') v = c - L'a' + 10;
        else if (c >= L'A' && c <= L'F') v = c - L'A' + 10;
        else if (iswspace(c))            continue;
        else                             return false;

        if (high < 0)
            high = v;
        else
        {
            out.push_back(static_cast<BYTE>((high << 4) | v));
            high = -1;
        }
    }
    return high < 0; // odd number of digits is invalid
}

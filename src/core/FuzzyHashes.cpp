// Similarity ("fuzzy") hashes: ssdeep and TLSH. Similar files get similar
// digests, so these are used to find variants of a file, not to verify it.

#include "core/Hashes.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

#include "core/TlshTables.inc"

std::wstring Widen(const std::string& s)
{
    return std::wstring(s.begin(), s.end());   // the digests are plain ASCII
}

// ---------------------------------------------------------------------------
// ssdeep (context triggered piecewise hashing, Jesse Kornblum 2006).
// Streaming form: the digests for all candidate block sizes are built in one
// pass, keeping only the block sizes that can still be chosen at the end, so
// the output matches the classic ssdeep tool without reading the data twice.
// ---------------------------------------------------------------------------
class SsdeepHasher : public Hasher
{
public:
    SsdeepHasher()
    {
        m_bh[0].h = m_bh[0].halfh = kHashInit;
    }

    void Update(const BYTE* data, size_t len) override
    {
        m_total += len;
        for (size_t i = 0; i < len; ++i)
            Step(data[i]);
    }

    std::vector<BYTE> Finish() override { return {}; }   // text digest only

    std::wstring FinishText() override
    {
        unsigned bi = m_start;
        const uint32_t h = RollSum();

        // Smallest block size that fits the whole input into the digest, then
        // smaller while that block size produced too few pieces.
        while (uint64_t(BlockSize(bi)) * kSpamSumLength < m_total)
        {
            if (++bi >= kNumBlockHashes)
                return L"(file too large for ssdeep)";
        }
        if (bi >= m_end)
            bi = m_end - 1;
        while (bi > m_start && m_bh[bi].dindex < kSpamSumLength / 2)
            --bi;

        std::string out = std::to_string(BlockSize(bi)) + ":";
        const BlockHash& first = m_bh[bi];
        out.append(first.digest, first.dindex);
        if (h != 0)
            out += kBase64[first.h % 64];
        else if (first.digest[first.dindex] != 0)
            out += first.digest[first.dindex];
        out += ':';

        if (bi < m_end - 1)
        {
            const BlockHash& second = m_bh[bi + 1];
            out.append(second.digest, std::min<unsigned>(second.dindex, kSpamSumLength / 2 - 1));
            if (h != 0)
                out += kBase64[second.halfh % 64];
            else if (second.halfdigest != 0)
                out += second.halfdigest;
        }
        else if (h != 0)
        {
            out += kBase64[(bi == 0 ? first.h : m_lastHash) % 64];
        }
        return Widen(out);
    }

private:
    static constexpr int kRollingWindow = 7;
    static constexpr uint32_t kMinBlockSize = 3;
    static constexpr unsigned kSpamSumLength = 64;
    static constexpr unsigned kNumBlockHashes = 31;
    static constexpr uint32_t kHashPrime = 0x01000193;
    static constexpr uint32_t kHashInit = 0x28021967;
    static constexpr char kBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    struct BlockHash
    {
        uint32_t h = 0;
        uint32_t halfh = 0;
        char digest[kSpamSumLength] = {};
        char halfdigest = 0;
        unsigned dindex = 0;
    };

    static uint32_t BlockSize(unsigned i) { return kMinBlockSize << i; }
    static uint32_t SumHash(BYTE c, uint32_t h) { return (h * kHashPrime) ^ c; }
    uint32_t RollSum() const { return m_h1 + m_h2 + m_h3; }

    void Roll(BYTE c)
    {
        m_h2 -= m_h1;
        m_h2 += kRollingWindow * static_cast<uint32_t>(c);
        m_h1 += c;
        m_h1 -= m_window[m_n];
        m_window[m_n] = c;
        if (++m_n == kRollingWindow)
            m_n = 0;
        m_h3 = (m_h3 << 5) ^ c;
    }

    // A block size gets its own state when the largest one triggers for the
    // first time; until then both have hashed exactly the same bytes.
    void Fork()
    {
        if (m_end < kNumBlockHashes)
        {
            const BlockHash& last = m_bh[m_end - 1];
            BlockHash& next = m_bh[m_end];
            next = BlockHash();
            next.h = last.h;
            next.halfh = last.halfh;
            ++m_end;
        }
        else if (!m_needLastHash)
        {
            m_needLastHash = true;
            m_lastHash = m_bh[m_end - 1].h;
        }
    }

    // Drops the smallest block size once it can no longer be chosen.
    void TryReduce()
    {
        if (m_end - m_start < 2)
            return;
        if (uint64_t(BlockSize(m_start)) * kSpamSumLength >= m_total)
            return;
        if (m_bh[m_start + 1].dindex < kSpamSumLength / 2)
            return;
        ++m_start;
    }

    void Step(BYTE c)
    {
        Roll(c);
        const uint32_t h = RollSum();
        for (unsigned i = m_start; i < m_end; ++i)
        {
            m_bh[i].h = SumHash(c, m_bh[i].h);
            m_bh[i].halfh = SumHash(c, m_bh[i].halfh);
        }
        if (m_needLastHash)
            m_lastHash = SumHash(c, m_lastHash);

        for (unsigned i = m_start; i < m_end; ++i)
        {
            // Block sizes double, so once one does not trigger, larger ones do not either.
            if (h % BlockSize(i) != BlockSize(i) - 1)
                break;
            BlockHash& b = m_bh[i];
            if (b.dindex == 0)
                Fork();
            b.digest[b.dindex] = kBase64[b.h % 64];
            b.halfdigest = kBase64[b.halfh % 64];
            if (b.dindex < kSpamSumLength - 1)
            {
                b.digest[++b.dindex] = 0;
                b.h = kHashInit;
                if (b.dindex < kSpamSumLength / 2)
                {
                    b.halfh = kHashInit;
                    b.halfdigest = 0;
                }
            }
            else
            {
                TryReduce();
            }
        }
    }

    BlockHash m_bh[kNumBlockHashes];
    unsigned m_start = 0;
    unsigned m_end = 1;
    bool m_needLastHash = false;
    uint32_t m_lastHash = 0;
    uint64_t m_total = 0;

    BYTE m_window[kRollingWindow] = {};
    uint32_t m_h1 = 0, m_h2 = 0, m_h3 = 0;
    unsigned m_n = 0;
};

// ---------------------------------------------------------------------------
// TLSH (Trend Micro Locality Sensitive Hash), standard form: 128 buckets,
// 1-byte checksum, "T1" + 70 hex digits. Needs at least 50 bytes of input.
// ---------------------------------------------------------------------------
class TlshHasher : public Hasher
{
public:
    void Update(const BYTE* data, size_t len) override
    {
        for (size_t n = 0; n < len; ++n, ++m_length)
        {
            const unsigned j = static_cast<unsigned>(m_length % 5);
            m_window[j] = data[n];
            if (m_length < 4)
                continue;
            const BYTE a = m_window[j];
            const BYTE b1 = m_window[(j + 4) % 5];
            const BYTE b2 = m_window[(j + 3) % 5];
            const BYTE b3 = m_window[(j + 2) % 5];
            const BYTE b4 = m_window[(j + 1) % 5];
            // The first arguments are kTlshPearson[salt] for salts 0, 2, 3, 5, 7, 11, 13.
            m_checksum = Map(1, a, b1, m_checksum);
            ++m_bucket[Map(49, a, b1, b2)];
            ++m_bucket[Map(12, a, b1, b3)];
            ++m_bucket[Map(178, a, b2, b3)];
            ++m_bucket[Map(166, a, b2, b4)];
            ++m_bucket[Map(84, a, b1, b4)];
            ++m_bucket[Map(230, a, b3, b4)];
        }
    }

    std::vector<BYTE> Finish() override { return {}; }   // text digest only

    std::wstring FinishText() override
    {
        constexpr unsigned kBuckets = 128;
        constexpr unsigned kCodeSize = 32;
        if (m_length < 50)
            return L"(needs at least 50 bytes)";
        if (m_length > 0xFFFFFFFFull)
            return L"(file too large for TLSH)";

        uint32_t sorted[kBuckets];
        std::copy(m_bucket, m_bucket + kBuckets, sorted);
        std::sort(sorted, sorted + kBuckets);
        const uint32_t q1 = sorted[kBuckets / 4 - 1];
        const uint32_t q2 = sorted[kBuckets / 2 - 1];
        const uint32_t q3 = sorted[kBuckets - kBuckets / 4 - 1];
        const unsigned nonZero = static_cast<unsigned>(std::count_if(m_bucket, m_bucket + kBuckets,
            [](uint32_t v) { return v > 0; }));
        if (q3 == 0 || nonZero <= kBuckets / 2)
            return L"(too little variation for TLSH)";

        BYTE code[kCodeSize];
        for (unsigned i = 0; i < kCodeSize; ++i)
        {
            BYTE h = 0;
            for (unsigned j = 0; j < 4; ++j)
            {
                const uint32_t k = m_bucket[4 * i + j];
                if (q3 < k)      h = static_cast<BYTE>(h + (3 << (j * 2)));
                else if (q2 < k) h = static_cast<BYTE>(h + (2 << (j * 2)));
                else if (q1 < k) h = static_cast<BYTE>(h + (1 << (j * 2)));
            }
            code[i] = h;
        }

        const uint32_t length = static_cast<uint32_t>(m_length);
        const BYTE lvalue = static_cast<BYTE>(std::min<size_t>(169,
            std::lower_bound(kTlshTopValue, kTlshTopValue + 170, length) - kTlshTopValue));
        const unsigned q1ratio = static_cast<unsigned>((uint64_t(q1) * 100 / q3) % 16);
        const unsigned q2ratio = static_cast<unsigned>((uint64_t(q2) * 100 / q3) % 16);
        const BYTE qbyte = static_cast<BYTE>(q1ratio | (q2ratio << 4));

        static const char kHex[] = "0123456789ABCDEF";
        std::string out = "T1";
        auto put = [&](BYTE b) { out += kHex[b >> 4]; out += kHex[b & 0x0F]; };
        put(Swap(m_checksum));
        put(Swap(lvalue));
        put(Swap(qbyte));
        for (unsigned i = 0; i < kCodeSize; ++i)
            put(code[kCodeSize - 1 - i]);
        return Widen(out);
    }

private:
    static BYTE Map(BYTE salt, BYTE i, BYTE j, BYTE k)
    {
        return kTlshPearson[kTlshPearson[kTlshPearson[salt ^ i] ^ j] ^ k];
    }

    static BYTE Swap(BYTE b) { return static_cast<BYTE>((b >> 4) | (b << 4)); }

    uint32_t m_bucket[256] = {};
    BYTE m_window[5] = {};
    BYTE m_checksum = 0;
    uint64_t m_length = 0;
};

} // namespace

std::unique_ptr<Hasher> CreateSsdeepHasher()
{
    return std::make_unique<SsdeepHasher>();
}

std::unique_ptr<Hasher> CreateTlshHasher()
{
    return std::make_unique<TlshHasher>();
}

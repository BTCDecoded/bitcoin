// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/blvm_utxo_snapshot.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <crypto/common.h>
#include <kernel/cs_main.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/translation.h>
#include <validation.h>

#include <cstdint>
#include <fstream>
#include <limits>
#include <memory>
#include <string_view>
#include <vector>

namespace kernel {
namespace {

static constexpr std::string_view BLVM_MAGIC{"BLVMUX01", 8};
static constexpr uint32_t BLVM_FORMAT_VERSION{1};
static constexpr uint32_t MAX_SCRIPT_BYTES{10'000};

static util::Result<void> ReadExact(std::ifstream& f, void* data, size_t len)
{
    f.read(static_cast<char*>(data), static_cast<std::streamsize>(len));
    if (!f || static_cast<size_t>(f.gcount()) != len) {
        return util::Error{Untranslated("BLVM snapshot: truncated file")};
    }
    return {};
}

// Read and validate the fixed-v1 file header; leave `f` positioned at the first entry.
// Returns {snap_height, entry_count}.
struct SnapshotHeader { uint64_t height; uint64_t entry_count; };
static util::Result<SnapshotHeader> ReadSnapshotHeader(std::ifstream& f)
{
    char magic[8];
    if (auto r{ReadExact(f, magic, 8)}; !r) return util::Error{util::ErrorString(r)};
    if (std::string_view{magic, 8} != BLVM_MAGIC) {
        return util::Error{Untranslated("BLVM snapshot: bad magic (expected BLVMUX01)")};
    }
    unsigned char u32buf[4];
    if (auto r{ReadExact(f, u32buf, 4)}; !r) return util::Error{util::ErrorString(r)};
    if (ReadLE32(u32buf) != BLVM_FORMAT_VERSION) {
        return util::Error{Untranslated("BLVM snapshot: unsupported format version")};
    }
    unsigned char u64buf[8];
    if (auto r{ReadExact(f, u64buf, 8)}; !r) return util::Error{util::ErrorString(r)};
    const uint64_t height = ReadLE64(u64buf);
    if (auto r{ReadExact(f, u64buf, 8)}; !r) return util::Error{util::ErrorString(r)};
    const uint64_t entry_count = ReadLE64(u64buf);
    return SnapshotHeader{height, entry_count};
}

// Load all UTXO entries from `f` (positioned right after the header) into `coins_cache`.
// Flushes periodically to avoid OOM.  Leaves `f` at EOF.
static util::Result<void> LoadEntries(std::ifstream& f, uint64_t entry_count, uint64_t snap_h,
                                       CCoinsViewCache& coins_cache, Chainstate& cs)
{
    unsigned char u32buf[4];
    unsigned char u64buf[8];
    uint64_t processed{0};
    while (processed < entry_count) {
        uint256 txid_u256;
        if (auto r{ReadExact(f, txid_u256.begin(), 32)}; !r) return r;
        if (auto r{ReadExact(f, u32buf, 4)}; !r) return r;
        const uint32_t vout = ReadLE32(u32buf);
        unsigned char i64buf[8];
        if (auto r{ReadExact(f, i64buf, 8)}; !r) return r;
        const int64_t n_value = ReadLE64(i64buf);
        if (auto r{ReadExact(f, u64buf, 8)}; !r) return r;
        const uint64_t coin_height_u64 = ReadLE64(u64buf);
        unsigned char cb;
        if (auto r{ReadExact(f, &cb, 1)}; !r) return r;
        if (auto r{ReadExact(f, u32buf, 4)}; !r) return r;
        const uint32_t script_len = ReadLE32(u32buf);
        if (script_len > MAX_SCRIPT_BYTES) {
            return util::Error{Untranslated(strprintf("BLVM snapshot: script too long (%u)", script_len))};
        }
        std::vector<unsigned char> script_data(script_len);
        if (script_len > 0) {
            if (auto r{ReadExact(f, script_data.data(), script_len)}; !r) return r;
        }
        if (coin_height_u64 > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
            return util::Error{Untranslated("BLVM snapshot: coin height overflow")};
        }
        if (static_cast<int>(coin_height_u64) > static_cast<int>(snap_h)) {
            return util::Error{Untranslated(strprintf(
                "BLVM snapshot: coin height %d exceeds snapshot height %d",
                static_cast<int>(coin_height_u64), static_cast<int>(snap_h)))};
        }
        CTxOut txout;
        txout.nValue = n_value;
        txout.scriptPubKey.assign(script_data.begin(), script_data.end());
        if (!MoneyRange(txout.nValue)) {
            return util::Error{Untranslated(strprintf(
                "BLVM snapshot: bad output amount at entry %u", static_cast<unsigned>(processed)))};
        }
        const Txid txid{Txid::FromUint256(txid_u256)};
        coins_cache.EmplaceCoinInternalDANGER(COutPoint{txid, vout},
                                               Coin{std::move(txout), static_cast<int>(coin_height_u64), cb != 0});
        ++processed;
        if (processed % 120000 == 0) {
            if (cs.GetCoinsCacheSizeState() >= CoinsCacheSizeState::CRITICAL) {
                coins_cache.SetBestBlock(GetRandHash());
                coins_cache.Flush();
            }
        }
    }
    // Trailing byte check
    std::byte extra{};
    f.read(reinterpret_cast<char*>(&extra), 1);
    if (f) {
        return util::Error{Untranslated("BLVM snapshot: trailing bytes after entries")};
    }
    return {};
}

} // namespace

util::Result<void> LoadBlvmUtxoSnapshotFixedV1(ChainstateManager& chainman, const fs::path& path)
{
    std::ifstream file{path.std_path(), std::ios::binary};
    if (!file) {
        return util::Error{Untranslated(strprintf("BLVM snapshot: cannot open %s", PathToString(path)))};
    }

    auto hdr = ReadSnapshotHeader(file);
    if (!hdr) return util::Error{util::ErrorString(hdr)};
    if (hdr->height > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
        return util::Error{Untranslated("BLVM snapshot: height overflow")};
    }
    const int snap_h = static_cast<int>(hdr->height);

    LOCK(::cs_main);
    Chainstate& cs = chainman.CurrentChainstate();
    CCoinsViewCache& coins_cache = cs.CoinsTip();
    CChain& chain = cs.m_chain;

    if (chain.Height() < 0) {
        return util::Error{Untranslated("BLVM snapshot: empty chain (sync headers/blocks through H first, or use SeedHeadlessChainstate)")};
    }
    if (chain.Height() != snap_h) {
        return util::Error{Untranslated(strprintf(
            "BLVM snapshot: file height %d but active tip height is %d (must match)",
            snap_h, chain.Height()))};
    }
    if (!coins_cache.GetBestBlock().IsNull()) {
        return util::Error{Untranslated(
            "BLVM snapshot: coins DB not empty — wipe chainstate DB before import")};
    }

    CBlockIndex* pindex = chain[snap_h];
    if (pindex == nullptr) {
        return util::Error{Untranslated("BLVM snapshot: missing block index for snapshot height")};
    }

    if (auto r{LoadEntries(file, hdr->entry_count, hdr->height, coins_cache, cs)}; !r) return r;

    coins_cache.SetBestBlock(pindex->GetBlockHash());
    cs.m_chain.SetTip(*pindex);
    coins_cache.Flush();
    return {};
}

util::Result<void> SeedHeadlessChainstate(
    ChainstateManager& chainman,
    const fs::path& snapshot_path,
    const std::vector<CBlockHeader>& headers,
    std::vector<std::unique_ptr<CBlockIndex>>& dummy_stub_storage,
    std::vector<uint256>& dummy_hash_storage)
{
    // `headers` must be a contiguous ascending run ending at the snapshot height.
    // Minimum 1 header (the snapshot tip itself). Providing the last 11 headers
    // gives correct GetMedianTimePast() results for nLockTime / CSV validation.
    if (headers.empty()) {
        return util::Error{Untranslated("SeedHeadlessChainstate: headers vector is empty")};
    }

    std::ifstream file{snapshot_path.std_path(), std::ios::binary};
    if (!file) {
        return util::Error{Untranslated(strprintf("SeedHeadlessChainstate: cannot open %s",
                                                  PathToString(snapshot_path)))};
    }

    auto hdr = ReadSnapshotHeader(file);
    if (!hdr) return util::Error{util::ErrorString(hdr)};
    if (hdr->height > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
        return util::Error{Untranslated("SeedHeadlessChainstate: snapshot height overflow")};
    }
    const int snap_h = static_cast<int>(hdr->height);

    // Validate that the last provided header is for the snapshot height.
    // We can't verify nHeight directly from the header, so we trust the caller's ordering.

    LOCK(::cs_main);
    Chainstate& cs = chainman.CurrentChainstate();
    CCoinsViewCache& coins_cache = cs.CoinsTip();

    if (!coins_cache.GetBestBlock().IsNull()) {
        return util::Error{Untranslated(
            "SeedHeadlessChainstate: coins DB not empty — wipe chainstate DB before seeding")};
    }

    // ── Build CBlockIndex stubs for the provided header range ───────────────────────────────
    // base_height is the height of headers[0]; the run is [base_height, base_height+N-1].
    const int n = static_cast<int>(headers.size());
    const int base_height = snap_h - n + 1;
    if (base_height < 0) {
        return util::Error{Untranslated(strprintf(
            "SeedHeadlessChainstate: %d headers would start at negative height %d for snap_h=%d",
            n, base_height, snap_h))};
    }

    // ── Lightweight dummy stubs for heights [0, base_height) ─────────────────────────────
    // Core's GetAncestor() walks pprev, so we need a full pprev chain from the tip to 0.
    // These stubs are NOT inserted into the block index map (so they're invisible to
    // pindexMostWork selection), but are heap-allocated and stored in dummy_stub_storage
    // to outlive this function call.  The real stubs hold pprev pointers to them.
    // ~50 bytes per stub → ~10 MB for 200k heights.
    dummy_stub_storage.clear();
    dummy_stub_storage.reserve(base_height);
    dummy_hash_storage.clear();
    dummy_hash_storage.reserve(base_height);
    CBlockIndex* prev_stub{nullptr};
    for (int h = 0; h < base_height; ++h) {
        // Allocate a stable synthetic hash BEFORE creating the stub, so the pointer stays valid.
        uint256& hash_slot = dummy_hash_storage.emplace_back();
        WriteLE32(hash_slot.begin(), static_cast<uint32_t>(h));        // encode height in bytes 0-3
        hash_slot.begin()[4] = 0xDD;                                    // sentinel byte

        auto stub = std::make_unique<CBlockIndex>();
        stub->nHeight    = h;
        stub->pprev      = prev_stub;
        stub->nStatus    = BLOCK_VALID_RESERVED;
        stub->nBits      = 0x1d00ffff;
        stub->nChainWork = (prev_stub ? prev_stub->nChainWork : arith_uint256{0}) + GetBlockProof(*stub);
        // Set a synthetic m_chain_tx_count so HaveNumChainTxs() returns true for the whole pprev
        // chain. This allows ReceivedBlockTransactions() to properly link blocks H+1 onward into
        // setBlockIndexCandidates instead of m_blocks_unlinked, enabling ActivateBestChain.
        stub->nTx              = 1;
        stub->m_chain_tx_count = static_cast<uint64_t>(h + 1);
        // Set phashBlock so GetBlockHash() doesn't assert on a dummy stub during chain traversal.
        stub->phashBlock = &hash_slot;
        prev_stub = stub.get();
        dummy_stub_storage.push_back(std::move(stub));
    }

    // Precompute hashes to avoid re-hashing inside the lock loop.
    std::vector<uint256> hashes;
    hashes.reserve(n);
    for (auto& h : headers) hashes.push_back(h.GetHash());

    // Insert real stubs for the header range [base_height, snap_h].
    // Non-tip stubs: BLOCK_VALID_CHAIN only (no HAVE_DATA/HAVE_UNDO — no block data on disk).
    // Tip stub (snap_h): BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO so Core
    // accepts it as fully-validated and SetTip succeeds. Core will never try to disconnect
    // the seeded tip because any incoming block is its direct successor.
    for (int i = 0; i < n; ++i) {
        CBlockIndex* stub = chainman.m_blockman.InsertBlockIndex(hashes[i]);
        if (stub->nHeight != 0 && stub->nHeight != base_height + i) {
            prev_stub = stub;
            continue;
        }
        stub->nHeight  = base_height + i;
        stub->nTime    = headers[i].nTime;
        stub->nBits    = headers[i].nBits;
        stub->nVersion = headers[i].nVersion;
        stub->pprev    = prev_stub;
        stub->nTimeMax = (prev_stub ? std::max(prev_stub->nTimeMax, stub->nTime) : stub->nTime);
        stub->nChainWork = (prev_stub ? prev_stub->nChainWork : arith_uint256{0}) + GetBlockProof(*stub);
        const bool is_tip = (base_height + i == snap_h);
        stub->nStatus = is_tip
            ? (BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)
            : BLOCK_VALID_CHAIN;
        stub->RaiseValidity(is_tip ? BLOCK_VALID_SCRIPTS : BLOCK_VALID_CHAIN);
        // Set synthetic m_chain_tx_count (same reason as dummy stubs above).
        stub->nTx              = 1;
        stub->m_chain_tx_count = static_cast<uint64_t>(stub->nHeight + 1);
        prev_stub = stub;
    }

    CBlockIndex* tip_stub = prev_stub;
    if (tip_stub == nullptr || tip_stub->nHeight != snap_h) {
        return util::Error{Untranslated(strprintf(
            "SeedHeadlessChainstate: stub chain tip height %d != snapshot height %d",
            tip_stub ? tip_stub->nHeight : -1, snap_h))};
    }

    // ── Load UTXO entries from snapshot ─────────────────────────────────────────────────────
    if (auto r{LoadEntries(file, hdr->entry_count, hdr->height, coins_cache, cs)}; !r) return r;

    // ── Commit chain tip ─────────────────────────────────────────────────────────────────────
    coins_cache.SetBestBlock(tip_stub->GetBlockHash());
    cs.m_chain.SetTip(*tip_stub);
    chainman.m_best_header = tip_stub;
    coins_cache.Flush();

    return {};
}

} // namespace kernel

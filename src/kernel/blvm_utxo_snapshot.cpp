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

    // ── Dummy stubs for heights [0, base_height) — inserted into block index for LevelDB persistence ──
    // Core's GetAncestor() walks pprev, so we need a full pprev chain from the tip to genesis.
    // We insert these via InsertBlockIndex so they are marked dirty and written to LevelDB on the
    // next flush.  This allows btck_chainstate_manager_create on restart to reconstruct pprev for
    // the first real stub (whose hashPrev is a synthetic hash only present here).  Without this
    // the pprev chain is incomplete after reload and LoadChainstate/VerifyLoadedChainstate fails.
    // Synthetic hashes: height in LE bytes 0-3, 0xDD sentinel in byte 4 — unique and recognizable.
    // Their nBits=0x1d00ffff → nChainWork well below the real chain, so pindexMostWork never selects
    // them; ActivateBestChains is deferred anyway (defer_activate_best_chains=true in all callers).
    dummy_stub_storage.clear();  // No longer storing manual unique_ptrs; kept for API compat.
    dummy_hash_storage.clear();  // Same; cleared for tidiness.
    CBlockIndex* prev_stub{nullptr};
    for (int h = 0; h < base_height; ++h) {
        uint256 dummy_hash;
        WriteLE32(dummy_hash.begin(), static_cast<uint32_t>(h));
        dummy_hash.begin()[4] = 0xDD;

        // InsertBlockIndex owns the CBlockIndex in m_block_index; phashBlock → map key (stable).
        CBlockIndex* stub = chainman.m_blockman.InsertBlockIndex(dummy_hash);
        if (stub->phashBlock != nullptr && stub->nHeight == h) {
            // Already seeded (e.g., re-entrant call); just walk the chain.
            prev_stub = stub;
            continue;
        }
        stub->nHeight    = h;
        stub->pprev      = prev_stub;
        stub->nStatus    = BLOCK_VALID_RESERVED;
        stub->nBits      = 0x1d00ffff;
        stub->nChainWork = (prev_stub ? prev_stub->nChainWork : arith_uint256{0}) + GetBlockProof(*stub);
        // Synthetic m_chain_tx_count so HaveNumChainTxs() returns true for the pprev chain.
        stub->nTx              = 1;
        stub->m_chain_tx_count = static_cast<uint64_t>(h + 1);
        // phashBlock is set by InsertBlockIndex to &mi->first (the map key) — already stable.
        prev_stub = stub;
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

util::Result<void> SeedHeadlessRestore(
    ChainstateManager& chainman,
    const std::vector<CBlockHeader>& headers,
    std::vector<std::unique_ptr<CBlockIndex>>& dummy_stub_storage,
    std::vector<uint256>& dummy_hash_storage)
{
    if (headers.empty()) {
        return util::Error{Untranslated("SeedHeadlessRestore: headers vector is empty")};
    }

    LOCK(::cs_main);
    Chainstate& cs = chainman.CurrentChainstate();
    CCoinsViewCache& coins_cache = cs.CoinsTip();

    if (coins_cache.GetBestBlock().IsNull()) {
        return util::Error{Untranslated(
            "SeedHeadlessRestore: coins DB is empty — use SeedHeadlessChainstate for initial seed")};
    }

    // Compute hashes for the provided headers so we can look them up in the block index.
    const int n = static_cast<int>(headers.size());
    std::vector<uint256> hashes;
    hashes.reserve(n);
    for (const auto& h : headers) hashes.push_back(h.GetHash());

    // Find base_height by looking up headers in the block index.
    // After the initial seed + at least one process_block call, the real stubs [base_height,
    // snap_h] were written to LevelDB and are present in m_blockman.m_block_index after reload.
    int base_height{-1};
    for (int i = 0; i < n && base_height < 0; ++i) {
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hashes[i]);
        if (pindex && pindex->nHeight >= i) {
            base_height = pindex->nHeight - i;
        }
    }
    if (base_height < 0) {
        return util::Error{Untranslated(
            "SeedHeadlessRestore: none of the provided headers found in block index — "
            "ensure at least one process_block call completed before the prior shutdown")};
    }
    const int snap_h = base_height + n - 1;

    // ── Dummy stubs for heights [0, base_height) ────────────────────────────────────────────────
    // Two cases depending on how the Core datadir was created:
    //
    //  NEW (fixed SeedHeadlessChainstate): dummy stubs were inserted via InsertBlockIndex and are
    //  already present in m_block_index after LoadBlockIndex.  pprev chain is intact; we just
    //  need the last dummy stub pointer to patch/verify the first real stub below.
    //
    //  OLD (pre-fix): dummy stubs were never written to LevelDB; pprev of the first real stub is
    //  nullptr after reload.  Rebuild them in-memory (dummy_stub_storage) and patch pprev.
    dummy_stub_storage.clear();
    dummy_hash_storage.clear();
    CBlockIndex* prev_stub{nullptr};

    if (base_height > 0) {
        // Probe for the height-0 dummy stub in the block map.
        uint256 probe_hash;
        WriteLE32(probe_hash.begin(), 0u);
        probe_hash.begin()[4] = 0xDD;
        const bool dummies_in_map = chainman.m_blockman.LookupBlockIndex(probe_hash) != nullptr;

        if (dummies_in_map) {
            // New-style datadir: find the last dummy stub so we can patch real stubs below.
            uint256 last_dummy_hash;
            WriteLE32(last_dummy_hash.begin(), static_cast<uint32_t>(base_height - 1));
            last_dummy_hash.begin()[4] = 0xDD;
            prev_stub = chainman.m_blockman.LookupBlockIndex(last_dummy_hash);
            // If lookup misses (shouldn't happen), fall through with prev_stub=nullptr; patching
            // below will still reconnect what it can.
        }

        if (!dummies_in_map || prev_stub == nullptr) {
            // Legacy path: dummy stubs not in LevelDB; build in-memory.
            dummy_stub_storage.reserve(base_height);
            dummy_hash_storage.reserve(base_height);
            prev_stub = nullptr;
            for (int h = 0; h < base_height; ++h) {
                uint256& hash_slot = dummy_hash_storage.emplace_back();
                WriteLE32(hash_slot.begin(), static_cast<uint32_t>(h));
                hash_slot.begin()[4] = 0xDD;

                auto stub = std::make_unique<CBlockIndex>();
                stub->nHeight          = h;
                stub->pprev            = prev_stub;
                stub->nStatus          = BLOCK_VALID_RESERVED;
                stub->nBits            = 0x1d00ffff;
                stub->nChainWork       = (prev_stub ? prev_stub->nChainWork : arith_uint256{0}) + GetBlockProof(*stub);
                stub->nTx              = 1;
                stub->m_chain_tx_count = static_cast<uint64_t>(h + 1);
                stub->phashBlock       = &hash_slot;
                prev_stub = stub.get();
                dummy_stub_storage.push_back(std::move(stub));
            }
        }
    }

    // ── Patch pprev for the real stubs [base_height, snap_h] ────────────────────────────────
    // In the new-style case pprev is already correct after LoadBlockIndex, but patching is
    // idempotent (only sets when nullptr) and cheap.
    for (int i = 0; i < n; ++i) {
        CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hashes[i]);
        if (!pindex) continue;
        if (pindex->pprev == nullptr) {
            pindex->pprev = prev_stub;
        }
        prev_stub = pindex;
    }

    // ── Restore m_chain.Tip() from the coins DB best-block hash ──────────────────────────────
    // The coins DB records the last block whose outputs were applied (updated by process_block).
    // It is at the actual chain tip, which may be higher than snap_h if process_block ran past it.
    const uint256& best_hash = coins_cache.GetBestBlock();
    CBlockIndex* tip = chainman.m_blockman.LookupBlockIndex(best_hash);
    if (!tip) {
        return util::Error{Untranslated(strprintf(
            "SeedHeadlessRestore: coins DB best block %s not found in block index",
            best_hash.ToString()))};
    }
    cs.m_chain.SetTip(*tip);
    chainman.m_best_header = tip;

    LogInfo("SeedHeadlessRestore: restored headless chain to height %d (snap_h=%d, base_height=%d, "
            "dummy_stubs=%zu)",
            tip->nHeight, snap_h, base_height, dummy_stub_storage.size());
    return {};
}

} // namespace kernel

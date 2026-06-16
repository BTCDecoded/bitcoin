// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BLVM_UTXO_SNAPSHOT_H
#define BITCOIN_KERNEL_BLVM_UTXO_SNAPSHOT_H

#include <util/result.h>

#include <memory>
#include <vector>

class CBlockIndex;
class CBlockHeader;
class ChainstateManager;
class uint256;

namespace fs {
class path;
}

namespace kernel {

/**
 * Load a BLVM fixed-v1 UTXO snapshot (magic "BLVMUX01") into the active chainstate.
 *
 * Preconditions:
 * - Active chain height equals the snapshot height (block index must be present through H).
 * - Coins DB has no best block yet (e.g. after wiping chainstate).
 *
 * For headless operation (no block index), use SeedHeadlessChainstate instead.
 */
util::Result<void> LoadBlvmUtxoSnapshotFixedV1(ChainstateManager& chainman, const fs::path& path);

/**
 * Seed a headless chainstate from a BLVM fixed-v1 UTXO snapshot without requiring a
 * pre-built block index.
 *
 * This is the intended path for differential testing: load utxo_0.bin + delta chain on the
 * Rust/BLVM side, write the result as a fixed-v1 snapshot, then call this to seed Core's
 * coins DB and create synthetic CBlockIndex stubs for the provided headers.  After this call,
 * process_block() can be used for blocks H+1 onward.
 *
 * @param chainman         ChainstateManager with an empty coins DB (wipe first if needed).
 * @param snapshot_path    Path to a fixed-v1 utxo_H.bin file (height H = headers.back()).
 * @param headers          Serialized block headers ending at height H, in ascending order.
 *                         Provide at least the last 11 headers for correct MedianTimePast;
 *                         providing fewer is allowed but may give wrong nLockTime results
 *                         for early blocks in the comparison window.
 *
 * Preconditions:
 * - Coins DB is empty (GetBestBlock().IsNull()).
 * - headers is non-empty; headers.back() is the header of the block at height H.
 * - snapshot_path contains a valid fixed-v1 file whose height matches headers.size() - 1
 *   relative to the last header's logical height.
 */
util::Result<void> SeedHeadlessChainstate(
    ChainstateManager& chainman,
    const fs::path& snapshot_path,
    const std::vector<CBlockHeader>& headers,
    std::vector<std::unique_ptr<CBlockIndex>>& dummy_stub_storage,
    std::vector<uint256>& dummy_hash_storage);

/**
 * Restore a headless chainstate after a process restart WITHOUT reloading the UTXO snapshot.
 *
 * After a process that called SeedHeadlessChainstate exits and restarts, the block index is
 * populated (real stubs were written to LevelDB by the first process_block call), but the
 * dummy pprev chain [0, base_height) is gone.  This function rebuilds just the dummy chain
 * and patches the dangling pprev pointer on the first real stub, then re-sets m_chain.Tip()
 * to the actual current best block from the coins DB.
 *
 * This avoids the ~10–50 GiB glibc heap fragmentation from re-reading and inserting 57M+
 * UTXO objects via CCoinsViewCache during a full SeedHeadlessChainstate restart.
 *
 * @param chainman            ChainstateManager whose coins DB is already populated (non-empty
 *                            GetBestBlock()) and whose block index has been loaded from LevelDB.
 * @param headers             The same ascending header run passed to the original
 *                            SeedHeadlessChainstate call (at minimum the headers window that
 *                            includes the snapshot height; same headers are required so that
 *                            pprev times are correct for GetMedianTimePast).
 * @param dummy_stub_storage  Out: receives the rebuilt dummy stubs [0, base_height).
 * @param dummy_hash_storage  Out: receives the synthetic hashes backing those stubs.
 *
 * Preconditions:
 * - Coins DB is populated (GetBestBlock() is non-null).
 * - Block index has been loaded (LoadBlockIndex already ran via LoadChainstate).
 * - At least one of the provided headers corresponds to a CBlockIndex in m_blockman.
 * - m_chainstate_manager_create was called with defer_activate_best_chains = true.
 */
util::Result<void> SeedHeadlessRestore(
    ChainstateManager& chainman,
    const std::vector<CBlockHeader>& headers,
    std::vector<std::unique_ptr<CBlockIndex>>& dummy_stub_storage,
    std::vector<uint256>& dummy_hash_storage);

} // namespace kernel

#endif // BITCOIN_KERNEL_BLVM_UTXO_SNAPSHOT_H

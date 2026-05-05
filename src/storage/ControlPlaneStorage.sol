// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BitmapNonces} from "../libraries/BitmapNonces.sol";

/// @title ControlPlaneStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Cluster.ControlPlane`.
/// @dev    Layout pinned in `docs/specs/control-plane-redesign.md` §5.2. The
///         `nonces` field embeds `BitmapNonces.Layout` directly so the facet
///         can hand a pointer-into-storage to the library's mutators without
///         a layout copy. The two scalar counters (`highestNonceSeen`,
///         `receiptCount`) are kept inline next to the bitmap so a
///         monitoring read of "where is this cluster" hits a single warm
///         word per scalar.
///
///         Slot literal derivation (locked, do not edit by hand):
///         ```
///         keccak256(abi.encode(uint256(keccak256("teesql.storage.Cluster.ControlPlane")) - 1))
///             & ~bytes32(uint256(0xff))
///         = 0xa4dc6767f8446ee077144bf661339e46e92ebc046d336548abe99700d0a6fb00
///         ```
///         Drift between this constant and the namespace string fails the
///         in-test slot derivation check (see `ControlPlaneFacet.t.sol`).
library ControlPlaneStorage {
    /// @custom:storage-location erc7201:teesql.storage.Cluster.ControlPlane
    struct Layout {
        // Bitmap-windowed nonce acceptance — see BitmapNonces.sol for the
        // full window semantics (rejects nonces >= 256 below the high-water
        // mark; accepts everything else exactly once).
        BitmapNonces.Layout nonces;
        // Per-(memberId, instructionId) acknowledgement-tracking. A receipt
        // for `(memberId, instructionId)` is rejected if the bit is already
        // set. Keys are kept tight so Etherscan log-decoders match the
        // event topic indexing without extra hash plumbing.
        mapping(bytes32 => mapping(bytes32 => bool)) memberJobsSeen;
        // Highest envelope nonce ever observed by `submitControl`. Mirrors
        // `nonces.lastNonce` for callers that don't want to reach into the
        // BitmapNonces layout — handy for chain-indexer cold-start logic
        // and Etherscan health probes.
        uint64 highestNonceSeen;
        // Monotonic counter of all accepted receipts. Cheap to read; useful
        // for a single-call "is this cluster making progress" probe without
        // having to walk the event log.
        uint64 receiptCount;
    }

    /// @dev See header for derivation. The slot literal is locked; the
    ///      facet's namespace-derivation self-check verifies this matches
    ///      `keccak(abi.encode(uint256(keccak("...")) - 1)) & ~0xff`.
    bytes32 internal constant SLOT = 0xa4dc6767f8446ee077144bf661339e46e92ebc046d336548abe99700d0a6fb00;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AdapterRegistryStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Cluster.AdapterRegistry`.
/// @dev    Two-axis adapter registry: attestation runtime × KMS service.
///         Slot literal pinned in spec §19.2.
library AdapterRegistryStorage {
    /// @custom:storage-location erc7201:teesql.storage.Cluster.AdapterRegistry
    struct Layout {
        // Per-passthrough axis assignments (set once at createMember time)
        mapping(address => bytes32) passthroughToAttestationId;
        mapping(address => bytes32) passthroughToKmsId;
        // Adapter facet pointers (rotated by Replace cuts + register* calls)
        mapping(bytes32 => address) attestationFacet;
        mapping(bytes32 => address) kmsFacet;
        // Soft-disable flags (Q8 — flip false to block new mints under that id)
        mapping(bytes32 => bool) attestationRegistered;
        mapping(bytes32 => bool) kmsRegistered;
        // Defaults for createMember convenience
        bytes32 defaultAttestationId;
        bytes32 defaultKmsId;
        // Enumeration support
        bytes32[] attestationIds;
        bytes32[] kmsIds;
    }

    bytes32 internal constant SLOT = 0x6ee2bb1ae478bac7e8c2d1f0e58e1f7a1636fb53a7bc4fcbf96fa7b68f3afb00;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

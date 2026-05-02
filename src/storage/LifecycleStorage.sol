// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LifecycleStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Cluster.Lifecycle`.
/// @dev    `destroyedAt != 0` is the irreversible "this proxy is forever
///         stranded" signal. `memberRetiredAt[id] != 0` removes a member
///         from elections and gates per-call-auth mutators. Reads stay live
///         post-destroy/retire so forensic tooling still resolves.
///         Slot literal pinned in spec §19.2.
library LifecycleStorage {
    /// @custom:storage-location erc7201:teesql.storage.Cluster.Lifecycle
    struct Layout {
        uint256 destroyedAt;
        mapping(bytes32 => uint256) memberRetiredAt;
    }

    bytes32 internal constant SLOT = 0xc40c1e00df80b3f4c543e37f29794c2b75c2c19948cdc128beef18bd67649200;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

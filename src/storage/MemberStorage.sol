// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MemberStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Member`.
/// @dev    Member proxy state. Set in `initialize(cluster)` once; never
///         written again. Same namespace constant across all per-runtime
///         Member impls (DstackMember today; future SecretMember etc.) so
///         the impls remain replaceable per runtime without storage shape
///         divergence. Slot literal pinned in spec §19.2.
library MemberStorage {
    /// @custom:storage-location erc7201:teesql.storage.Member
    struct Layout {
        address cluster;
    }

    bytes32 internal constant SLOT = 0x48806f0bd1843d40ee54b27b1aa46bd5d77ad5ef1d133812b356f098b9410500;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

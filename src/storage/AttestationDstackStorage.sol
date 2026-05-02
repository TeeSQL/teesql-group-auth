// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AttestationDstackStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Attestation.Dstack`.
/// @dev    dstack-runtime-specific policy state. Slot literal pinned in spec §19.2.
library AttestationDstackStorage {
    /// @custom:storage-location erc7201:teesql.storage.Attestation.Dstack
    struct Layout {
        bool requireTcbUpToDate;
    }

    bytes32 internal constant SLOT = 0xd7792075c59b42042554c184711f2bbdb0cf33034e870c3d398f5dda38b39300;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

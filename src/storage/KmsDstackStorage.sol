// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title KmsDstackStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Kms.Dstack`.
/// @dev    dstack-KMS-specific trust state: KMS pointer, root allowlist.
///         Slot literal pinned in spec §19.2.
library KmsDstackStorage {
    /// @custom:storage-location erc7201:teesql.storage.Kms.Dstack
    struct Layout {
        address kms; // dstack-KMS registry pointer (calls IDstackKms.registerApp)
        mapping(address => bool) allowedKmsRoots; // sig-chain trust anchors
    }

    bytes32 internal constant SLOT = 0x0a600982a64d34a5ac3f1d20f4d5803cd76af3217f9a5da226acbf0cb783a200;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

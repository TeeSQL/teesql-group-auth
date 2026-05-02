// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AllowlistsStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Cluster.Allowlists`.
/// @dev    Provider-agnostic boot policy + signer mgmt. BootGate reads;
///         AdminFacet writes. Slot literal pinned in spec §19.2.
library AllowlistsStorage {
    /// @custom:storage-location erc7201:teesql.storage.Cluster.Allowlists
    struct Layout {
        mapping(bytes32 => bool) allowedComposeHashes;
        mapping(bytes32 => bool) allowedDeviceIds;
        bool allowAnyDevice;
        mapping(address => AuthorizedSigner) authorizedSigners;
    }

    struct AuthorizedSigner {
        uint8 permissions;
        bool active;
        uint256 authorizedAt;
    }

    bytes32 internal constant SLOT =
        0xcdbccb570e3ddeff5f78f96ecefff8bfca6530b9eb528384193698ff8c203000;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

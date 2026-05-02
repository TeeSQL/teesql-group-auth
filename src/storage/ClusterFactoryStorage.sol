// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ClusterFactoryStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.ClusterFactory`.
/// @dev    `ClusterDiamondFactory`'s state: Ownable2Step admin role +
///         per-deployed-cluster provenance map + enumeration array.
///         Slot literal pinned in
///         `docs/specs/cluster-diamond-factory-and-member-provenance.md` §3.3
///         and `docs/specs/cluster-v4-diamond-and-member-uups.md` §19.2.
///         Drift between this constant and the spec tables fails CI
///         (`test/SpecConstants.t.sol`).
library ClusterFactoryStorage {
    /// @custom:storage-location erc7201:teesql.storage.ClusterFactory
    struct Layout {
        address admin;
        address pendingAdmin; // Ownable2Step
        mapping(address => bool) deployedClusters;
        address[] registeredClusters;
    }

    bytes32 internal constant SLOT = 0x3dde469251f57f7dd4cc59a0b621bdd53104456939a109094995dee88fec1700;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

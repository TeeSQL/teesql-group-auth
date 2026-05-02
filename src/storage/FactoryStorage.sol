// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title FactoryStorage
/// @notice ERC-7201 storage accessor for `teesql.storage.Factory`.
/// @dev    Per-runtime Member impl mapping + Ownable2Step admin state.
///         Slot literal pinned in spec §19.2.
library FactoryStorage {
    /// @custom:storage-location erc7201:teesql.storage.Factory
    struct Layout {
        address admin;
        address pendingAdmin; // Ownable2Step
        mapping(bytes32 => address) memberImpl; // attestationId → impl
        bytes32[] registeredAttestationIds; // for enumeration
        // Per-member provenance map. Set in deployMember(); never cleared.
        // Webhook + hub fleet enumeration consume this via isDeployedMember.
        // Append-only ERC-7201 layout extension; safe vs prior on-chain
        // factory state (this is a fresh factory deploy, not an in-place
        // upgrade — see spec §3.2).
        mapping(address => bool) deployedMembers;
    }

    bytes32 internal constant SLOT = 0xc7ca5b180fe1e18defad477f0b08739bf72851d8efc9aa269b38f4d8139d4e00;

    function layout() internal pure returns (Layout storage l) {
        bytes32 slot = SLOT;
        assembly {
            l.slot := slot
        }
    }
}

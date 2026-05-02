// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CoreStorage} from "../storage/CoreStorage.sol";
import {LifecycleStorage} from "../storage/LifecycleStorage.sol";
import {AllowlistsStorage} from "../storage/AllowlistsStorage.sol";

/// @title ViewFacet
/// @notice Diamond facet exposing explicit getters for ERC-7201 fields not
///         already auto-exposed by their owning facets. Holds no state.
/// @dev    Per spec §6.7: ABI-stable, isolated for cheap swaps. All reads go
///         through the standard `_layout()` accessor pattern (storage-library
///         link, never logic-library link — see §13.4).
contract ViewFacet {
    // ─── Cluster.Core ──────────────────────────────────────────────────────

    function clusterId() external view returns (string memory) {
        return CoreStorage.layout().clusterId;
    }

    function nextMemberSeq() external view returns (uint256) {
        return CoreStorage.layout().nextMemberSeq;
    }

    function factory() external view returns (address) {
        return CoreStorage.layout().factory;
    }

    // ─── Cluster.Lifecycle ─────────────────────────────────────────────────

    function destroyedAt() external view returns (uint256) {
        return LifecycleStorage.layout().destroyedAt;
    }

    function destroyed() external view returns (bool) {
        return LifecycleStorage.layout().destroyedAt != 0;
    }

    function memberRetiredAt(bytes32 memberId) external view returns (uint256) {
        return LifecycleStorage.layout().memberRetiredAt[memberId];
    }

    // ─── Cluster.Allowlists ────────────────────────────────────────────────

    function allowedComposeHashes(bytes32 h) external view returns (bool) {
        return AllowlistsStorage.layout().allowedComposeHashes[h];
    }

    function allowedDeviceIds(bytes32 d) external view returns (bool) {
        return AllowlistsStorage.layout().allowedDeviceIds[d];
    }

    function allowAnyDevice() external view returns (bool) {
        return AllowlistsStorage.layout().allowAnyDevice;
    }

    function authorizedSigners(address s) external view returns (uint8 permissions, bool active, uint256 authorizedAt) {
        AllowlistsStorage.AuthorizedSigner storage signer = AllowlistsStorage.layout().authorizedSigners[s];
        return (signer.permissions, signer.active, signer.authorizedAt);
    }

    function isSignerAuthorized(address s, uint8 required) external view returns (bool) {
        AllowlistsStorage.AuthorizedSigner storage signer = AllowlistsStorage.layout().authorizedSigners[s];
        return signer.active && (signer.permissions & required) == required;
    }
}

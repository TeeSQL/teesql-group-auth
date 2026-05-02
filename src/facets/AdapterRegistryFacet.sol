// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAdapterRegistry} from "../interfaces/IAdapterRegistry.sol";
import {AdapterRegistryStorage} from "../storage/AdapterRegistryStorage.sol";

/// @title AdapterRegistryFacet
/// @notice Read-only view facet over the two-axis adapter registry
///         (attestation runtime x KMS service). Mutators live on AdminFacet.
contract AdapterRegistryFacet is IAdapterRegistry {
    function _$() private pure returns (AdapterRegistryStorage.Layout storage) {
        return AdapterRegistryStorage.layout();
    }

    function attestationFor(address passthrough) external view returns (bytes32) {
        return _$().passthroughToAttestationId[passthrough];
    }

    function kmsFor(address passthrough) external view returns (bytes32) {
        return _$().passthroughToKmsId[passthrough];
    }

    function attestationFacet(bytes32 attestationId) external view returns (address) {
        return _$().attestationFacet[attestationId];
    }

    function kmsFacet(bytes32 kmsId) external view returns (address) {
        return _$().kmsFacet[kmsId];
    }

    function attestationRegistered(bytes32 attestationId) external view returns (bool) {
        return _$().attestationRegistered[attestationId];
    }

    function kmsRegistered(bytes32 kmsId) external view returns (bool) {
        return _$().kmsRegistered[kmsId];
    }

    function defaultAttestationId() external view returns (bytes32) {
        return _$().defaultAttestationId;
    }

    function defaultKmsId() external view returns (bytes32) {
        return _$().defaultKmsId;
    }

    function listAttestationIds() external view returns (bytes32[] memory) {
        return _$().attestationIds;
    }

    function listKmsIds() external view returns (bytes32[] memory) {
        return _$().kmsIds;
    }
}

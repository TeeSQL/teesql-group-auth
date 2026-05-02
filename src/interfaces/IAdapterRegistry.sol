// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAdapterRegistry
/// @notice AdapterRegistryFacet's external surface — two-axis registry
///         (attestation runtime × KMS service). Mutators live on AdminFacet.
interface IAdapterRegistry {
    function attestationFor(address passthrough) external view returns (bytes32);
    function kmsFor(address passthrough) external view returns (bytes32);
    function attestationFacet(bytes32 attestationId) external view returns (address);
    function kmsFacet(bytes32 kmsId) external view returns (address);
    function attestationRegistered(bytes32 attestationId) external view returns (bool);
    function kmsRegistered(bytes32 kmsId) external view returns (bool);
    function defaultAttestationId() external view returns (bytes32);
    function defaultKmsId() external view returns (bytes32);
    function listAttestationIds() external view returns (bytes32[] memory);
    function listKmsIds() external view returns (bytes32[] memory);
}

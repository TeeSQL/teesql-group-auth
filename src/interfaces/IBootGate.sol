// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IBootGate
/// @notice BootGateFacet's external surface — provider-agnostic cluster-wide
///         boot policy. Per-runtime adapters layer their own gates on top.
interface IBootGate {
    /// Cluster-wide checks: destroyedAt, paused, isOurPassthrough,
    /// allowedComposeHashes, allowAnyDevice || allowedDeviceIds.
    /// Returns (false, reason) on any failure, (true, "") on pass.
    function clusterBootPolicy(address passthrough, bytes32 composeHash, bytes32 deviceId)
        external
        view
        returns (bool ok, string memory reason);
}

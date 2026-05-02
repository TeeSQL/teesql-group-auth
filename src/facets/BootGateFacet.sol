// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IBootGate} from "../interfaces/IBootGate.sol";
import {CoreStorage} from "../storage/CoreStorage.sol";
import {AllowlistsStorage} from "../storage/AllowlistsStorage.sol";
import {LifecycleStorage} from "../storage/LifecycleStorage.sol";

/// @title BootGateFacet
/// @notice Provider-agnostic cluster-wide boot policy. Per-runtime adapters
///         layer their own gates on top.
contract BootGateFacet is IBootGate {
    function clusterBootPolicy(address passthrough, bytes32 composeHash, bytes32 deviceId)
        external
        view
        returns (bool ok, string memory reason)
    {
        if (LifecycleStorage.layout().destroyedAt != 0) {
            return (false, "cluster destroyed");
        }
        CoreStorage.Layout storage c = CoreStorage.layout();
        if (c.paused) {
            return (false, "cluster paused");
        }
        if (!c.isOurPassthrough[passthrough]) {
            return (false, "unknown passthrough");
        }
        AllowlistsStorage.Layout storage a = AllowlistsStorage.layout();
        if (!a.allowedComposeHashes[composeHash]) {
            return (false, "compose hash not allowed");
        }
        if (!a.allowAnyDevice && !a.allowedDeviceIds[deviceId]) {
            return (false, "device not allowed");
        }
        return (true, "");
    }
}

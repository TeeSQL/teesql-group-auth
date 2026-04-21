// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title IAppAuth
/// @notice Core interface for dstack App Authentication contracts.
/// @dev    Mirrored from dstack/kms/auth-eth/contracts/IAppAuth.sol so we can
///         compile against a local copy without a git-submodule dependency.
///         Interface ID: 0x1e079198
interface IAppAuth is IERC165 {
    struct AppBootInfo {
        address appId;
        bytes32 composeHash;
        address instanceId;
        bytes32 deviceId;
        bytes32 mrAggregated;
        bytes32 mrSystem;
        bytes32 osImageHash;
        string tcbStatus;
        string[] advisoryIds;
    }

    function isAppAllowed(AppBootInfo calldata bootInfo) external view returns (bool isAllowed, string memory reason);
}

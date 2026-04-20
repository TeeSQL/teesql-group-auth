// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title IAppAuthBasicManagement
/// @notice Management interface for admin UIs to manage compose-hash and device-id allowlists.
/// @dev    Mirrored from dstack/kms/auth-eth/contracts/IAppAuthBasicManagement.sol.
///         Interface ID: 0x8fd37527
interface IAppAuthBasicManagement is IERC165 {
    event ComposeHashAdded(bytes32 composeHash);
    event ComposeHashRemoved(bytes32 composeHash);
    event DeviceAdded(bytes32 deviceId);
    event DeviceRemoved(bytes32 deviceId);

    function addComposeHash(bytes32 composeHash) external;
    function removeComposeHash(bytes32 composeHash) external;
    function addDevice(bytes32 deviceId) external;
    function removeDevice(bytes32 deviceId) external;
}

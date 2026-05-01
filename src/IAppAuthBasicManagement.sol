// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title IAppAuthBasicManagement
/// @notice Management interface for admin UIs to manage compose-hash, device-id,
///         and TCB-policy state on a dstack-style app contract, plus the
///         symmetric read surface that operator tooling (phala-cli, dashboards)
///         uses for pre-flight verification.
/// @dev    Mirrored from dstack/kms/auth-eth/contracts/IAppAuthBasicManagement.sol.
interface IAppAuthBasicManagement is IERC165 {
    event ComposeHashAdded(bytes32 composeHash);
    event ComposeHashRemoved(bytes32 composeHash);
    event DeviceAdded(bytes32 deviceId);
    event DeviceRemoved(bytes32 deviceId);
    event AllowAnyDeviceSet(bool allowAny);
    event RequireTcbUpToDateSet(bool requireUpToDate);

    function addComposeHash(bytes32 composeHash) external;
    function removeComposeHash(bytes32 composeHash) external;
    function addDevice(bytes32 deviceId) external;
    function removeDevice(bytes32 deviceId) external;
    function setAllowAnyDevice(bool allowAny) external;
    function setRequireTcbUpToDate(bool requireUpToDate) external;

    function allowedComposeHashes(bytes32 composeHash) external view returns (bool);
    function allowedDeviceIds(bytes32 deviceId) external view returns (bool);
    function allowAnyDevice() external view returns (bool);
    function requireTcbUpToDate() external view returns (bool);
    function owner() external view returns (address);
    function version() external view returns (uint256);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAppAuth} from "./IAppAuth.sol";
import {IAppAuthBasicManagement} from "./IAppAuthBasicManagement.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice Minimal read surface we forward to the parent cluster. The member
///         is intentionally non-upgradeable and holds no state of its own;
///         these getters mirror what `DstackApp.sol` (the dstack reference
///         app contract) exposes via its `mapping public` declarations and
///         OZ `OwnableUpgradeable`. Phala-cli + dstack tooling read these
///         on a CVM's `app_id` during in-place updates; without them the
///         caller can't tell our member apart from a non-conforming proxy.
interface IClusterReadOnly {
    function owner() external view returns (address);
    function allowedComposeHashes(bytes32) external view returns (bool);
    function allowedDeviceIds(bytes32) external view returns (bool);
    function allowAnyDevice() external view returns (bool);
}

/// @title TeeSqlClusterMember
/// @notice Per-CVM passthrough that forwards IAppAuth.isAppAllowed to a TeeSqlClusterApp.
/// @dev No mutable storage, no admin, no upgrade path. Exists only to give each CVM a unique
///      address usable as its DstackKms `app_id`. All logic and state live on the cluster
///      contract. `cluster` is an immutable baked into bytecode at construction.
contract TeeSqlClusterMember is IAppAuth {
    /// @notice The TeeSqlClusterApp this passthrough routes to.
    address public immutable cluster;

    error ClusterZero();

    constructor(address _cluster) {
        if (_cluster == address(0)) revert ClusterZero();
        cluster = _cluster;
    }

    /// @inheritdoc IAppAuth
    /// @dev Called by DstackKms during CVM boot with `bootInfo.appId == address(this)`.
    ///      We forward unchanged; the cluster validates compose hash, device id, and
    ///      defensively checks `isOurPassthrough[bootInfo.appId]`.
    function isAppAllowed(AppBootInfo calldata bootInfo)
        external
        view
        override
        returns (bool isAllowed, string memory reason)
    {
        return IAppAuth(cluster).isAppAllowed(bootInfo);
    }

    /// @notice Forwards to the parent cluster's `owner()`.
    /// @dev Not part of `IAppAuth.sol` (which is intentionally agnostic about
    ///      authorization patterns), but the Phala CLI's in-place CVM-update
    ///      flow (`phala deploy --cvm-id …`) auto-registers devices by
    ///      reading `owner()` on the CVM's `app_id` and signing the
    ///      `addDevice` tx as that EOA. Without this passthrough the CLI
    ///      reverts on `owner()` and refuses to ship sidecar image upgrades.
    ///
    ///      Returning the cluster's owner is the right answer: that's the
    ///      EOA (or Safe) authorised to call `addDevice` / `addComposeHash`
    ///      on the parent — exactly what the CLI then attempts to do.
    function owner() external view returns (address) {
        return IClusterReadOnly(cluster).owner();
    }

    /// @notice Forward `allowedComposeHashes(hash)` to the parent cluster.
    /// @dev Phala's commit-update backend (and other dstack tooling) reads
    ///      this getter on the CVM's `app_id` to confirm an upgrade-target
    ///      compose hash is on-chain-allowlisted. The reference
    ///      `DstackApp.sol` exposes it as the auto-getter from
    ///      `mapping(bytes32 => bool) public allowedComposeHashes`. Our
    ///      cluster pattern keeps the storage on the parent so it's shared
    ///      across N member proxies; the member just forwards the read.
    ///
    ///      Pairs with the experiment in
    ///      `dstackgres/docs/bug-reports/phala-cli-cvm-update-cluster-app-id.md`
    ///      to test whether Failure 2 is satisfied by member-side getter
    ///      passthroughs.
    function allowedComposeHashes(bytes32 h) external view returns (bool) {
        return IClusterReadOnly(cluster).allowedComposeHashes(h);
    }

    /// @notice Forward `allowedDeviceIds(deviceId)` to the parent cluster.
    /// @dev Same reasoning as `allowedComposeHashes` above.
    function allowedDeviceIds(bytes32 d) external view returns (bool) {
        return IClusterReadOnly(cluster).allowedDeviceIds(d);
    }

    /// @notice Forward `allowAnyDevice()` to the parent cluster.
    /// @dev DstackApp.sol exposes this as a flag that, when true, skips
    ///      the device-id allowlist check. Forwarding lets Phala's
    ///      pre-flight reach the same answer the boot path would.
    function allowAnyDevice() external view returns (bool) {
        return IClusterReadOnly(cluster).allowAnyDevice();
    }

    error NotClusterOwner();

    /// @notice Forward `addComposeHash(hash)` to the parent cluster.
    /// @dev phala-cli's in-place CVM-update flow signs an `addComposeHash`
    ///      tx targeting the CVM's `app_id`. We accept the call from the
    ///      cluster's owner EOA only and forward through. The cluster's
    ///      `addComposeHash` recognises this passthrough as one of its
    ///      registered members (`isOurPassthrough[msg.sender]`) and
    ///      accepts the call — so end-to-end the only authority that can
    ///      mutate the allowlist via this path is the cluster owner, the
    ///      same as a direct call to `cluster.addComposeHash(hash)`.
    function addComposeHash(bytes32 h) external {
        if (msg.sender != IClusterReadOnly(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).addComposeHash(h);
    }

    /// @notice Forward `removeComposeHash(hash)` to the parent cluster.
    /// @dev Same gating as `addComposeHash`.
    function removeComposeHash(bytes32 h) external {
        if (msg.sender != IClusterReadOnly(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).removeComposeHash(h);
    }

    /// @notice Forward `addDevice(deviceId)` to the parent cluster.
    /// @dev Same gating as `addComposeHash`.
    function addDevice(bytes32 d) external {
        if (msg.sender != IClusterReadOnly(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).addDevice(d);
    }

    /// @notice Forward `removeDevice(deviceId)` to the parent cluster.
    /// @dev Same gating as `addComposeHash`.
    function removeDevice(bytes32 d) external {
        if (msg.sender != IClusterReadOnly(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).removeDevice(d);
    }

    function supportsInterface(bytes4 id) external pure override returns (bool) {
        return id == type(IAppAuth).interfaceId
            || id == type(IAppAuthBasicManagement).interfaceId
            || id == type(IERC165).interfaceId;
    }
}

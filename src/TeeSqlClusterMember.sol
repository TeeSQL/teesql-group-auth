// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAppAuth} from "./IAppAuth.sol";
import {IAppAuthBasicManagement} from "./IAppAuthBasicManagement.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title TeeSqlClusterMember
/// @notice Per-CVM passthrough that forwards admin and boot-gate calls to a TeeSqlClusterApp.
/// @dev No mutable storage, no admin, no upgrade path. Exists only to give each CVM a unique
///      address usable as its DstackKms `app_id`. All logic and state live on the cluster
///      contract. `cluster` is an immutable baked into bytecode at construction.
///
///      Inherits `IAppAuthBasicManagement` (not `IAppAuth`) because the member's *own*
///      authoritative surface is the management forward — phala-cli reads/writes the
///      compose-hash and device allowlists on the CVM's `app_id`, and we expose those
///      functions natively as a registered interface. `isAppAllowed` exists too, but it's
///      a thin relay to the cluster (which is the IAppAuth implementer) rather than a
///      decision this contract makes; we still advertise IAppAuth via supportsInterface.
///
///      All read forwarders below cast `cluster` as `IAppAuthBasicManagement`. After the
///      interface expansion (added `owner`, allowlist getters, `version`, the TCB-policy
///      surface), the management interface itself covers every read we forward, so a
///      separate ad-hoc read interface is no longer needed.
contract TeeSqlClusterMember is IAppAuthBasicManagement {
    /// @notice The TeeSqlClusterApp this passthrough routes to.
    address public immutable cluster;

    error ClusterZero();

    constructor(address _cluster) {
        if (_cluster == address(0)) revert ClusterZero();
        cluster = _cluster;
    }

    /// @notice Forward `IAppAuth.isAppAllowed` to the parent cluster.
    /// @dev Called by DstackKms during CVM boot with `bootInfo.appId == address(this)`.
    ///      We forward unchanged; the cluster validates compose hash, device id, and
    ///      defensively checks `isOurPassthrough[bootInfo.appId]`. Not an `override` —
    ///      this contract no longer inherits `IAppAuth` — but the selector is the same
    ///      so DstackKms's `IAppAuth(appId).isAppAllowed(..)` ABI call still resolves.
    function isAppAllowed(IAppAuth.AppBootInfo calldata bootInfo)
        external
        view
        returns (bool isAllowed, string memory reason)
    {
        return IAppAuth(cluster).isAppAllowed(bootInfo);
    }

    /// @notice Forwards to the parent cluster's `owner()`.
    /// @dev Phala CLI's in-place CVM-update flow (`phala deploy --cvm-id …`)
    ///      auto-registers devices by reading `owner()` on the CVM's `app_id`
    ///      and signing the `addDevice` tx as that EOA. Returning the cluster's
    ///      owner is the right answer: that EOA (or Safe) is exactly the one
    ///      authorized to call `addDevice` / `addComposeHash` on the parent.
    function owner() external view override returns (address) {
        return IAppAuthBasicManagement(cluster).owner();
    }

    /// @notice Forwards the cluster impl's `version()`. Operator-facing
    ///         identity for "which logic is the proxy running?". Tracks the
    ///         cluster impl across UUPS upgrades; the member itself is
    ///         non-upgradeable, so this number changes only when the cluster
    ///         is upgraded.
    function version() external view override returns (uint256) {
        return IAppAuthBasicManagement(cluster).version();
    }

    /// @notice Forward `allowedComposeHashes(hash)` to the parent cluster.
    /// @dev Phala's commit-update backend (and other dstack tooling) reads
    ///      this getter on the CVM's `app_id` to confirm an upgrade-target
    ///      compose hash is on-chain-allowlisted. The reference
    ///      `DstackApp.sol` exposes it as the auto-getter from
    ///      `mapping(bytes32 => bool) public allowedComposeHashes`. Our
    ///      cluster pattern keeps the storage on the parent so it's shared
    ///      across N member proxies; the member just forwards the read.
    function allowedComposeHashes(bytes32 h) external view override returns (bool) {
        return IAppAuthBasicManagement(cluster).allowedComposeHashes(h);
    }

    /// @notice Forward `allowedDeviceIds(deviceId)` to the parent cluster.
    /// @dev Same reasoning as `allowedComposeHashes` above.
    function allowedDeviceIds(bytes32 d) external view override returns (bool) {
        return IAppAuthBasicManagement(cluster).allowedDeviceIds(d);
    }

    /// @notice Forward `allowAnyDevice()` to the parent cluster.
    /// @dev DstackApp.sol exposes this as a flag that, when true, skips
    ///      the device-id allowlist check. Forwarding lets Phala's
    ///      pre-flight reach the same answer the boot path would.
    function allowAnyDevice() external view override returns (bool) {
        return IAppAuthBasicManagement(cluster).allowAnyDevice();
    }

    /// @notice Forward `requireTcbUpToDate()` to the parent cluster.
    /// @dev Currently informational on TeeSqlClusterApp — the cluster's
    ///      `isAppAllowed` does not consult it. Operator tooling may still
    ///      read it as a config policy. If the cluster ever begins enforcing
    ///      TCB freshness at boot, this getter remains the canonical readback.
    function requireTcbUpToDate() external view override returns (bool) {
        return IAppAuthBasicManagement(cluster).requireTcbUpToDate();
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
    function addComposeHash(bytes32 h) external override {
        if (msg.sender != IAppAuthBasicManagement(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).addComposeHash(h);
    }

    /// @notice Forward `removeComposeHash(hash)` to the parent cluster.
    /// @dev Same gating as `addComposeHash`.
    function removeComposeHash(bytes32 h) external override {
        if (msg.sender != IAppAuthBasicManagement(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).removeComposeHash(h);
    }

    /// @notice Forward `addDevice(deviceId)` to the parent cluster.
    /// @dev Same gating as `addComposeHash`.
    function addDevice(bytes32 d) external override {
        if (msg.sender != IAppAuthBasicManagement(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).addDevice(d);
    }

    /// @notice Forward `removeDevice(deviceId)` to the parent cluster.
    /// @dev Same gating as `addComposeHash`.
    function removeDevice(bytes32 d) external override {
        if (msg.sender != IAppAuthBasicManagement(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).removeDevice(d);
    }

    /// @notice Forward `setAllowAnyDevice(bool)` to the parent cluster.
    /// @dev Same gating as `addComposeHash`. The cluster's `setAllowAnyDevice`
    ///      accepts owner-or-passthrough, so the end-to-end authority is the
    ///      cluster owner regardless of which path is taken.
    function setAllowAnyDevice(bool v) external override {
        if (msg.sender != IAppAuthBasicManagement(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).setAllowAnyDevice(v);
    }

    /// @notice Forward `setRequireTcbUpToDate(bool)` to the parent cluster.
    /// @dev Same gating as `addComposeHash`.
    function setRequireTcbUpToDate(bool v) external override {
        if (msg.sender != IAppAuthBasicManagement(cluster).owner()) revert NotClusterOwner();
        IAppAuthBasicManagement(cluster).setRequireTcbUpToDate(v);
    }

    function supportsInterface(bytes4 id) external pure override returns (bool) {
        return id == type(IAppAuth).interfaceId
            || id == type(IAppAuthBasicManagement).interfaceId
            || id == type(IERC165).interfaceId;
    }
}

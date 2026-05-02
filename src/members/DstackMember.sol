// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IERC173} from "@solidstate/contracts/interfaces/IERC173.sol";

import {IAppAuth} from "../IAppAuth.sol";
import {IAppAuthBasicManagement} from "../IAppAuthBasicManagement.sol";
import {IAdmin} from "../interfaces/IAdmin.sol";
import {IDstackAttestationAdapter} from "../interfaces/IDstackAttestationAdapter.sol";
import {MemberStorage} from "../storage/MemberStorage.sol";

/// @title DstackMember
/// @notice Per-CVM Member proxy implementation for the dstack attestation
///         runtime. Exposes the dstack-shape ABI (`IAppAuth` +
///         `IAppAuthBasicManagement`) that DstackKms and phala-cli expect,
///         and forwards every call into the per-cluster diamond using the
///         provider-namespaced selectors documented in spec
///         `cluster-v4-diamond-and-member-uups.md` §6 + §7.
/// @dev    UUPS impl. `cluster` is set once in `initialize`. Upgrade
///         authority reads `cluster.owner()` at call time so Safe-owner
///         rotations propagate to every member without per-member action;
///         additionally, member upgrades are blocked once the cluster has
///         been destroyed (spec §7.4). Storage layout is the
///         `teesql.storage.Member` ERC-7201 namespace shared across every
///         per-runtime Member impl.
contract DstackMember is Initializable, UUPSUpgradeable, IAppAuth, IAppAuthBasicManagement {
    error ClusterZero();
    error NotClusterOwner();
    error ClusterDestroyed_();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// One-shot initializer invoked by `ERC1967Proxy`'s constructor via the
    /// `ClusterMemberFactory`. Binds this Member proxy to the cluster
    /// diamond it forwards into for the rest of its lifetime.
    function initialize(address _cluster) external initializer {
        if (_cluster == address(0)) revert ClusterZero();
        MemberStorage.layout().cluster = _cluster;
    }

    /// The cluster diamond this Member is bound to.
    function cluster() external view returns (address) {
        return MemberStorage.layout().cluster;
    }

    // ── IAppAuth ────────────────────────────────────────────────────────────
    // DstackKms calls this at boot. Forward to the dstack attestation
    // adapter's namespaced entry point.

    function isAppAllowed(AppBootInfo calldata b) external view returns (bool, string memory) {
        return IDstackAttestationAdapter(MemberStorage.layout().cluster).dstack_isAppAllowed(b);
    }

    // ── IAppAuthBasicManagement mutators ────────────────────────────────────
    // Cluster-wide selectors (compose hash, device, allowAny) forward bare to
    // AdminFacet; dstack-runtime-specific selectors (TCB) forward to the
    // namespaced dstack adapter. All gated on `cluster.owner()` at the
    // Member level (defense in depth — the diamond also enforces).

    function addComposeHash(bytes32 h) external {
        address c = MemberStorage.layout().cluster;
        if (msg.sender != IERC173(c).owner()) revert NotClusterOwner();
        IAdmin(c).addComposeHash(h);
    }

    function removeComposeHash(bytes32 h) external {
        address c = MemberStorage.layout().cluster;
        if (msg.sender != IERC173(c).owner()) revert NotClusterOwner();
        IAdmin(c).removeComposeHash(h);
    }

    function addDevice(bytes32 d) external {
        address c = MemberStorage.layout().cluster;
        if (msg.sender != IERC173(c).owner()) revert NotClusterOwner();
        IAdmin(c).addDevice(d);
    }

    function removeDevice(bytes32 d) external {
        address c = MemberStorage.layout().cluster;
        if (msg.sender != IERC173(c).owner()) revert NotClusterOwner();
        IAdmin(c).removeDevice(d);
    }

    function setAllowAnyDevice(bool v) external {
        address c = MemberStorage.layout().cluster;
        if (msg.sender != IERC173(c).owner()) revert NotClusterOwner();
        IAdmin(c).setAllowAnyDevice(v);
    }

    function setRequireTcbUpToDate(bool v) external {
        address c = MemberStorage.layout().cluster;
        if (msg.sender != IERC173(c).owner()) revert NotClusterOwner();
        IDstackAttestationAdapter(c).dstack_setRequireTcbUpToDate(v);
    }

    // ── IAppAuthBasicManagement views ───────────────────────────────────────

    function allowedComposeHashes(bytes32 h) external view returns (bool) {
        return IView(MemberStorage.layout().cluster).allowedComposeHashes(h);
    }

    function allowedDeviceIds(bytes32 d) external view returns (bool) {
        return IView(MemberStorage.layout().cluster).allowedDeviceIds(d);
    }

    function allowAnyDevice() external view returns (bool) {
        return IView(MemberStorage.layout().cluster).allowAnyDevice();
    }

    function requireTcbUpToDate() external view returns (bool) {
        return IDstackAttestationAdapter(MemberStorage.layout().cluster).dstack_requireTcbUpToDate();
    }

    function owner() external view returns (address) {
        return IERC173(MemberStorage.layout().cluster).owner();
    }

    /// dstack-mirror `version()` — forwards to the dstack adapter's runtime
    /// version so the phala-cli expected ABI is preserved while the diamond
    /// never directly exposes a bare `version()` selector.
    function version() external view returns (uint256) {
        return IDstackAttestationAdapter(MemberStorage.layout().cluster).dstack_version();
    }

    /// Member impl's own counter — distinct selector from the dstack-mirror
    /// `version()` above. Bumped on each Member impl revision.
    function memberImplVersion() external pure returns (uint256) {
        return 1;
    }

    // ── Lifecycle reads (forwarded to ViewFacet) ────────────────────────────

    function destroyedAt() external view returns (uint256) {
        return IView(MemberStorage.layout().cluster).destroyedAt();
    }

    function destroyed() external view returns (bool) {
        return IView(MemberStorage.layout().cluster).destroyed();
    }

    function memberRetiredAt(bytes32 id) external view returns (uint256) {
        return IView(MemberStorage.layout().cluster).memberRetiredAt(id);
    }

    // ── ERC-165 ────────────────────────────────────────────────────────────

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(IAppAuth).interfaceId || id == type(IAppAuthBasicManagement).interfaceId
            || id == type(IERC165).interfaceId;
    }

    // ── UUPS authorization ─────────────────────────────────────────────────
    // Per spec §7.4: gated on `cluster.owner()` AND the cluster not being
    // destroyed. The latter prevents the "cluster is dead but members keep
    // upgrading" footgun where an operator could rotate to an impl that
    // points at a different cluster's adapters or breaks the cluster-bound
    // storage shape.

    function _authorizeUpgrade(address) internal view override {
        address c = MemberStorage.layout().cluster;
        if (msg.sender != IERC173(c).owner()) revert NotClusterOwner();
        if (IView(c).destroyedAt() != 0) revert ClusterDestroyed_();
    }
}

/// @notice Minimal local interface for the diamond's ViewFacet — only the
///         view selectors `DstackMember` consumes. Kept inline so a Member
///         impl bake never accidentally pulls in unrelated ViewFacet
///         surface area.
interface IView {
    function allowedComposeHashes(bytes32) external view returns (bool);
    function allowedDeviceIds(bytes32) external view returns (bool);
    function allowAnyDevice() external view returns (bool);
    function destroyedAt() external view returns (uint256);
    function destroyed() external view returns (bool);
    function memberRetiredAt(bytes32) external view returns (uint256);
}

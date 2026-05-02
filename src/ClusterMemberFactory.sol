// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {IClusterMemberFactory, IMemberInit} from "./interfaces/IClusterMemberFactory.sol";
import {FactoryStorage} from "./storage/FactoryStorage.sol";

/// @title ClusterMemberFactory
/// @notice UUPS chain-singleton factory that deploys `ERC1967Proxy`
///         Member instances bound to a per-cluster diamond. Per-runtime
///         impl selection: the factory keeps a `attestationId → impl`
///         mapping; each `deployMember` call selects the impl matching
///         the cluster's attestation runtime. Storage lives in the
///         `teesql.storage.Factory` ERC-7201 namespace shared with
///         every future revision of this contract.
/// @dev    Spec: `cluster-v4-diamond-and-member-uups.md` §8 +
///         `cluster-diamond-factory-and-member-provenance.md` §3.0,
///         §3.2. UUPS rework supersedes parent §8 Q9 (which framed this
///         factory as non-upgradeable); the webhook trust pin
///         (`CANONICAL_MEMBER_FACTORY` env) requires a stable proxy
///         address across factory bytecode revisions.
///
///         Admin (`Ownable2Step`) is intentionally distinct from any
///         cluster's owner — the same Safe can hold both, but
///         separating the roles documents the trust boundary (admin
///         can rotate a per-runtime Member impl across every cluster
///         that uses that runtime).
contract ClusterMemberFactory is Initializable, UUPSUpgradeable, IClusterMemberFactory {
    error NotImplemented();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// One-shot initializer invoked by `ERC1967Proxy`'s constructor at
    /// chain-bootstrap time. Replaces the prior direct constructor.
    function initialize(address _admin) external initializer {
        if (_admin == address(0)) revert ZeroAddress();
        FactoryStorage.layout().admin = _admin;
    }

    /// Reinitializer placeholder per repo UUPS convention
    /// (memory: feedback_uups_reinitializer_convention). v1 reverts;
    /// future impl revisions override with `reinitializer(N)` and the
    /// appropriate migration logic, then ship via:
    ///   factory.upgradeToAndCall(newImpl, abi.encodeCall(reinitialize, (N, data)))
    function reinitialize(
        uint64,
        /*version*/
        bytes calldata /*data*/
    )
        public
        virtual
    {
        revert NotImplemented();
    }

    /// UUPS upgrade gate. Same `onlyAdmin` authority as `setMemberImpl`
    /// / `transferAdmin`. Admin starts as deployer EOA, transfers to a
    /// Safe via `transferAdmin` / `acceptAdmin`.
    function _authorizeUpgrade(address) internal view override onlyAdmin {}

    modifier onlyAdmin() {
        if (msg.sender != FactoryStorage.layout().admin) revert NotAdmin();
        _;
    }

    // ── Reads ──────────────────────────────────────────────────────────────

    function memberImpl(bytes32 attestationId) external view returns (address) {
        return FactoryStorage.layout().memberImpl[attestationId];
    }

    function admin() external view returns (address) {
        return FactoryStorage.layout().admin;
    }

    function pendingAdmin() external view returns (address) {
        return FactoryStorage.layout().pendingAdmin;
    }

    function registeredAttestationIds() external view returns (bytes32[] memory) {
        return FactoryStorage.layout().registeredAttestationIds;
    }

    // ── Per-runtime impl management ────────────────────────────────────────

    /// Set or rotate the Member impl for a specific attestation runtime.
    /// First call for a given `attestationId` registers that runtime in
    /// `registeredAttestationIds`; subsequent calls rotate the impl
    /// (existing members are untouched — only future deploys land on the
    /// new impl, see spec §8.2).
    function setMemberImpl(bytes32 attestationId, address newImpl) external onlyAdmin {
        if (attestationId == bytes32(0) || newImpl == address(0)) {
            revert ZeroAddress();
        }
        FactoryStorage.Layout storage $ = FactoryStorage.layout();
        address oldImpl = $.memberImpl[attestationId];
        if (newImpl == oldImpl) revert ImplUnchanged();
        $.memberImpl[attestationId] = newImpl;
        if (oldImpl == address(0)) {
            $.registeredAttestationIds.push(attestationId);
        }
        emit MemberImplUpdated(attestationId, oldImpl, newImpl);
    }

    // ── Ownable2Step admin transfer ────────────────────────────────────────

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        FactoryStorage.layout().pendingAdmin = newAdmin;
        emit AdminTransferStarted(msg.sender, newAdmin);
    }

    function acceptAdmin() external {
        FactoryStorage.Layout storage $ = FactoryStorage.layout();
        if (msg.sender != $.pendingAdmin) revert NotPendingAdmin();
        address previousAdmin = $.admin;
        $.admin = msg.sender;
        $.pendingAdmin = address(0);
        emit AdminTransferred(previousAdmin, msg.sender);
    }

    // ── Deploy ─────────────────────────────────────────────────────────────

    /// Deploy a Member proxy bound to (`cluster`, `attestationId`).
    /// Permissionless — the cluster's `createMember` orchestrator is the
    /// natural caller. The deployed proxy is inert until the cluster
    /// registers it (Core marks `isOurPassthrough` and the AdapterRegistry
    /// records the two-axis assignment).
    function deployMember(address cluster, bytes32 salt, bytes32 attestationId) public returns (address proxy) {
        if (cluster == address(0)) revert ZeroAddress();
        address impl = FactoryStorage.layout().memberImpl[attestationId];
        if (impl == address(0)) revert ImplNotRegistered();

        bytes32 effectiveSalt = keccak256(abi.encode(cluster, attestationId, salt));
        bytes memory initCalldata = abi.encodeCall(IMemberInit.initialize, (cluster));
        proxy = address(new ERC1967Proxy{salt: effectiveSalt}(impl, initCalldata));
        FactoryStorage.layout().deployedMembers[proxy] = true;
        emit MemberDeployed(cluster, salt, attestationId, proxy, impl);
    }

    /// Webhook + hub fleet enumeration consume this. Returns true iff
    /// `proxy` was minted by this factory's `deployMember` path. False
    /// for any externally-deployed proxy at the same address (defends
    /// against a rogue contract claiming to be one of our members).
    function isDeployedMember(address proxy) external view returns (bool) {
        return FactoryStorage.layout().deployedMembers[proxy];
    }

    /// Predict the address `deployMember(cluster, salt, attestationId)`
    /// would return, using the CURRENT `memberImpl[attestationId]`.
    /// @dev Result becomes stale if `memberImpl[attestationId]` rotates
    ///      between predict and deploy. Operators (and Core's
    ///      `createMember`) should use `deployMemberWithExpectedImpl` to
    ///      pin the impl atomically — see spec §8.3.
    function predict(address cluster, bytes32 salt, bytes32 attestationId) external view returns (address) {
        address impl = FactoryStorage.layout().memberImpl[attestationId];
        if (impl == address(0)) revert ImplNotRegistered();
        bytes32 effectiveSalt = keccak256(abi.encode(cluster, attestationId, salt));
        bytes memory initCalldata = abi.encodeCall(IMemberInit.initialize, (cluster));
        bytes memory bytecode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initCalldata));
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), effectiveSalt, keccak256(bytecode))))
            )
        );
    }

    /// Atomic variant of `deployMember` — reverts with `ImplDriftDetected`
    /// if `memberImpl[attestationId]` has rotated since the caller predicted
    /// the address. Core's `createMember` calls this; operator tooling
    /// should too.
    function deployMemberWithExpectedImpl(address cluster, bytes32 salt, bytes32 attestationId, address expectedImpl)
        external
        returns (address proxy)
    {
        if (FactoryStorage.layout().memberImpl[attestationId] != expectedImpl) {
            revert ImplDriftDetected();
        }
        return deployMember(cluster, salt, attestationId);
    }
}

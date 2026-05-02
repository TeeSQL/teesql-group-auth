// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC173} from "@solidstate/contracts/interfaces/IERC173.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {DiamondSmokeTest} from "../DiamondSmoke.t.sol";

import {DstackMember} from "src/members/DstackMember.sol";
import {MemberStorage} from "src/storage/MemberStorage.sol";

import {ICore} from "src/interfaces/ICore.sol";
import {IAdmin} from "src/interfaces/IAdmin.sol";
import {IDstackKmsAdapter} from "src/interfaces/IDstackKmsAdapter.sol";
import {IDstackAttestationAdapter} from "src/interfaces/IDstackAttestationAdapter.sol";
import {IAppAuth} from "src/IAppAuth.sol";
import {IAppAuthBasicManagement} from "src/IAppAuthBasicManagement.sol";

/// @notice Tiny v2 impl used by the upgrade tests. Standalone (does NOT
///         inherit `DstackMember`) because `memberImplVersion()` and
///         `cluster()` etc. on the v1 impl are non-virtual and the test
///         constraint forbids editing `src/`. Shares the same
///         `teesql.storage.Member` ERC-7201 namespace via `MemberStorage`,
///         so post-upgrade the cluster pointer set by v1's `initialize`
///         is still readable through this contract.
///
///         Selector design:
///         - `memberImplVersion()` returns 2 (v1 returns 1) → primary
///           "behavior swapped" probe.
///         - `pinged()` is brand new — proves a v2-exclusive selector
///           dispatches through the proxy.
///         - `cluster()` reads the same ERC-7201 slot v1 wrote → proves
///           storage continuity across the upgrade.
///         - `_authorizeUpgrade` mirrors v1 so subsequent re-upgrades
///           still gate on `cluster.owner()` and not-destroyed.
contract DstackMemberV2 is Initializable, UUPSUpgradeable {
    error NotClusterOwner();
    error ClusterDestroyed_();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function cluster() external view returns (address) {
        return MemberStorage.layout().cluster;
    }

    function memberImplVersion() external pure returns (uint256) {
        return 2;
    }

    /// New selector that did not exist on v1 — proof that the v2 bytecode is
    /// being dispatched after `upgradeToAndCall`.
    function pinged() external pure returns (bool) {
        return true;
    }

    function _authorizeUpgrade(address) internal view override {
        address c = MemberStorage.layout().cluster;
        if (msg.sender != IERC173(c).owner()) revert NotClusterOwner();
        if (_IView(c).destroyedAt() != 0) revert ClusterDestroyed_();
    }
}

/// @dev Minimal local interface — only `destroyedAt`, used by V2's
///      `_authorizeUpgrade` lifecycle gate. Same shape as the
///      `IView` declared in DstackMember.sol; redeclared here to keep
///      the test impl self-contained.
interface _IView {
    function destroyedAt() external view returns (uint256);
}

/// @notice Spec-§7 unit tests for `DstackMember` per-CVM UUPS Member proxy.
///         Inherits `DiamondSmokeTest` for its facet-cut helpers and the
///         chain-singleton factory + dstack runtime registration. We do NOT
///         override the parent's `setUp()` (it isn't virtual) — instead
///         each test calls `_initFixture()` which is idempotent over the
///         no-op fields and seeds a fresh per-test member.
///
/// Coverage focus: `src/members/DstackMember.sol`, including both
/// `_authorizeUpgrade` branches (non-owner caller AND destroyed-cluster
/// gate). Pre-suite baseline was 14.75% (9/61 lines).
contract DstackMemberTest is DiamondSmokeTest {
    DstackMember internal member;
    address internal nonOwner;

    /// @dev EIP-1967 implementation slot:
    ///      `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`.
    ///      Value confirmed against
    ///      `lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol`.
    bytes32 internal constant EIP1967_IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // ─── Fixture (called from each test) ───────────────────────────────────

    /// Build the diamond + KMS pointer + a single registered member proxy
    /// that the per-test forwarders read/write through. The parent's
    /// no-arg `setUp()` (deploys the chain singletons + facets) runs
    /// automatically before this; we layer the diamond + member on top.
    ///
    /// The Member is minted via `ICore.createMember` (NOT
    /// `factory.deployMember` directly) so the diamond's `isOurPassthrough`
    /// is set — without that, AdminFacet's
    /// `_requireOwnerOrPassthrough(msg.sender)` rejects every Member-
    /// forwarded mutator with `NotAuthorized()`.
    function _initFixture() internal {
        nonOwner = address(0xBEEF);
        _buildDiamond();
        IDstackKmsAdapter(address(diamond)).dstack_kms_setKms(address(mockKms));
        member = DstackMember(
            ICore(address(diamond)).createMember(bytes32(uint256(0x1001)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID)
        );
    }

    /// Deploy a fresh DstackMember proxy bound to this test's diamond via
    /// the chain-singleton factory directly. Skips the AdapterRegistry +
    /// `isOurPassthrough` writes that `CoreFacet.createMember` does — so
    /// the resulting member's mutator forwarders will revert with
    /// `NotAuthorized()` from the diamond side. Used by the
    /// `isAppAllowed_propagatesRejectReason` test which deliberately
    /// wants a member that BootGate considers an "unknown passthrough".
    function _freshMemberRaw(bytes32 salt) internal returns (address) {
        return factory.deployMember(address(diamond), salt, DSTACK_ATTESTATION_ID);
    }

    /// Build a minimal `AppBootInfo` payload for the IAppAuth tests.
    function _bootInfo(address passthrough, bytes32 composeHash, string memory tcbStatus)
        internal
        pure
        returns (IAppAuth.AppBootInfo memory b)
    {
        b = IAppAuth.AppBootInfo({
            appId: passthrough,
            composeHash: composeHash,
            instanceId: address(0xDEAD),
            deviceId: bytes32(0),
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: tcbStatus,
            advisoryIds: new string[](0)
        });
    }

    // ─── Initialization (3 tests) ──────────────────────────────────────────

    function test_initialize_setsClusterAndCannotBeCalledTwice() public {
        _initFixture();

        // _freshMember already initialized via the proxy ctor — verify the
        // cluster pointer is set to the diamond.
        assertEq(member.cluster(), address(diamond), "cluster pointer");

        // Re-calling initialize on an already-initialized proxy must revert
        // with OZ Initializable's `InvalidInitialization()` (the storage
        // version slot is non-zero).
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        DstackMember(address(member)).initialize(address(0xDEAD));
    }

    function test_initialize_revertsOnZeroCluster() public {
        // The factory's `deployMember` rejects `cluster == 0` with its own
        // `ZeroAddress()` BEFORE reaching the proxy ctor, so to exercise
        // the member's own `ClusterZero` guard we instantiate ERC1967Proxy
        // directly here, bypassing the factory's pre-check.
        vm.expectRevert(DstackMember.ClusterZero.selector);
        new ERC1967Proxy(address(dstackMemberImpl), abi.encodeCall(DstackMember.initialize, (address(0))));
    }

    function test_implContractCannotBeInitialized() public view {
        // Calling initialize directly on the impl (not via a proxy) must
        // revert because the impl's ctor invokes `_disableInitializers`,
        // which sets `_initialized = type(uint64).max`. We assert via a
        // staticcall + low-level check so the view modifier on this test
        // is honored (no state changes attempted on the impl).
        (bool ok, bytes memory ret) =
            address(dstackMemberImpl).staticcall(abi.encodeCall(DstackMember.initialize, (address(0xCAFE))));
        assertFalse(ok, "init on impl should revert");
        // ret should encode the 4-byte InvalidInitialization selector.
        bytes4 sel;
        assembly { sel := mload(add(ret, 0x20)) }
        assertEq(sel, Initializable.InvalidInitialization.selector, "expected error sel");
    }

    // ─── IAppAuth forwarder (2 tests) ──────────────────────────────────────

    function test_isAppAllowed_forwardsToDstackAdapter_happyPath() public {
        _initFixture();
        // The setUp's `member` is already a registered passthrough on the
        // diamond (`isOurPassthrough = true`).
        IAdmin(address(diamond)).setAllowAnyDevice(true);
        IAdmin(address(diamond)).addComposeHash(SOME_HASH);

        // Happy path: tcb gate off, should pass.
        (bool ok, string memory reason) = member.isAppAllowed(_bootInfo(address(member), SOME_HASH, "UpToDate"));
        assertTrue(ok, reason);
        assertEq(bytes(reason).length, 0, "no reason on success");

        // Now flip the tcb gate on and pass a non-UpToDate status. The
        // diamond's dstack adapter is the layer that checks tcbStatus;
        // verifying that flipping it changes the result proves the call
        // actually traversed the dstack adapter (not just BootGate).
        IDstackAttestationAdapter(address(diamond)).dstack_setRequireTcbUpToDate(true);
        (bool ok2, string memory reason2) = member.isAppAllowed(_bootInfo(address(member), SOME_HASH, "OutOfDate"));
        assertFalse(ok2, "tcb gate should reject OutOfDate");
        assertEq(reason2, "tcb not up to date", "tcb reason text");
    }

    function test_isAppAllowed_propagatesRejectReason() public {
        _initFixture();
        // Mint a fresh "raw" member (via factory directly) that is NOT a
        // registered passthrough on the diamond. BootGate should reject
        // with "unknown passthrough" — and that string must surface
        // unmodified through the Member's forwarder.
        DstackMember rawMember = DstackMember(_freshMemberRaw(bytes32(uint256(0xDEAD0001))));
        IAdmin(address(diamond)).addComposeHash(SOME_HASH);
        (bool ok, string memory reason) = rawMember.isAppAllowed(_bootInfo(address(rawMember), SOME_HASH, "UpToDate"));
        assertFalse(ok, "should reject unknown passthrough");
        assertEq(reason, "unknown passthrough", "reason propagation");
    }

    // ─── IAppAuthBasicManagement mutator forwarders (12 tests) ─────────────
    // For each of: addComposeHash, removeComposeHash, addDevice,
    // removeDevice, setAllowAnyDevice, setRequireTcbUpToDate
    // — one happy path (cluster owner) + one revert (non-owner). The
    // forwarder gate reads `cluster.owner()` at call time, so the deployer
    // (= owner via SolidStateDiamond's ctor) is always the legitimate caller.

    function test_addComposeHash_succeedsFromClusterOwner() public {
        _initFixture();
        bytes32 h = bytes32(uint256(0xAA));
        member.addComposeHash(h);
        assertTrue(IAppAuthBasicManagement(address(diamond)).allowedComposeHashes(h), "compose hash present on diamond");
    }

    function test_addComposeHash_revertsForNonOwner() public {
        _initFixture();
        vm.prank(nonOwner);
        vm.expectRevert(DstackMember.NotClusterOwner.selector);
        member.addComposeHash(bytes32(uint256(0xAA)));
    }

    function test_removeComposeHash_succeedsFromClusterOwner() public {
        _initFixture();
        bytes32 h = bytes32(uint256(0xAB));
        member.addComposeHash(h);
        member.removeComposeHash(h);
        assertFalse(IAppAuthBasicManagement(address(diamond)).allowedComposeHashes(h), "compose hash cleared");
    }

    function test_removeComposeHash_revertsForNonOwner() public {
        _initFixture();
        vm.prank(nonOwner);
        vm.expectRevert(DstackMember.NotClusterOwner.selector);
        member.removeComposeHash(bytes32(uint256(0xAB)));
    }

    function test_addDevice_succeedsFromClusterOwner() public {
        _initFixture();
        bytes32 d = bytes32(uint256(0xD0));
        member.addDevice(d);
        assertTrue(IAppAuthBasicManagement(address(diamond)).allowedDeviceIds(d), "device present on diamond");
    }

    function test_addDevice_revertsForNonOwner() public {
        _initFixture();
        vm.prank(nonOwner);
        vm.expectRevert(DstackMember.NotClusterOwner.selector);
        member.addDevice(bytes32(uint256(0xD0)));
    }

    function test_removeDevice_succeedsFromClusterOwner() public {
        _initFixture();
        bytes32 d = bytes32(uint256(0xD1));
        member.addDevice(d);
        member.removeDevice(d);
        assertFalse(IAppAuthBasicManagement(address(diamond)).allowedDeviceIds(d), "device cleared");
    }

    function test_removeDevice_revertsForNonOwner() public {
        _initFixture();
        vm.prank(nonOwner);
        vm.expectRevert(DstackMember.NotClusterOwner.selector);
        member.removeDevice(bytes32(uint256(0xD1)));
    }

    function test_setAllowAnyDevice_succeedsFromClusterOwner() public {
        _initFixture();
        member.setAllowAnyDevice(true);
        assertTrue(IAppAuthBasicManagement(address(diamond)).allowAnyDevice(), "allowAnyDevice true on diamond");
        member.setAllowAnyDevice(false);
        assertFalse(IAppAuthBasicManagement(address(diamond)).allowAnyDevice(), "allowAnyDevice false on diamond");
    }

    function test_setAllowAnyDevice_revertsForNonOwner() public {
        _initFixture();
        vm.prank(nonOwner);
        vm.expectRevert(DstackMember.NotClusterOwner.selector);
        member.setAllowAnyDevice(true);
    }

    function test_setRequireTcbUpToDate_succeedsFromClusterOwner() public {
        _initFixture();
        member.setRequireTcbUpToDate(true);
        assertTrue(
            IDstackAttestationAdapter(address(diamond)).dstack_requireTcbUpToDate(), "tcb requirement on diamond"
        );
        member.setRequireTcbUpToDate(false);
        assertFalse(
            IDstackAttestationAdapter(address(diamond)).dstack_requireTcbUpToDate(), "tcb requirement off on diamond"
        );
    }

    function test_setRequireTcbUpToDate_revertsForNonOwner() public {
        _initFixture();
        vm.prank(nonOwner);
        vm.expectRevert(DstackMember.NotClusterOwner.selector);
        member.setRequireTcbUpToDate(true);
    }

    // ─── IAppAuthBasicManagement view forwarders (6 tests) ─────────────────

    function test_allowedComposeHashes_forwards() public {
        _initFixture();
        bytes32 h = bytes32(uint256(0xCAFE));
        assertFalse(member.allowedComposeHashes(h), "absent before");
        IAdmin(address(diamond)).addComposeHash(h);
        assertTrue(member.allowedComposeHashes(h), "present after");
    }

    function test_allowedDeviceIds_forwards() public {
        _initFixture();
        bytes32 d = bytes32(uint256(0xBEAD));
        assertFalse(member.allowedDeviceIds(d), "absent before");
        IAdmin(address(diamond)).addDevice(d);
        assertTrue(member.allowedDeviceIds(d), "present after");
    }

    function test_allowAnyDevice_forwards() public {
        _initFixture();
        assertFalse(member.allowAnyDevice(), "default false");
        IAdmin(address(diamond)).setAllowAnyDevice(true);
        assertTrue(member.allowAnyDevice(), "true after flip");
    }

    function test_requireTcbUpToDate_forwards() public {
        _initFixture();
        assertFalse(member.requireTcbUpToDate(), "default false");
        IDstackAttestationAdapter(address(diamond)).dstack_setRequireTcbUpToDate(true);
        assertTrue(member.requireTcbUpToDate(), "true after flip");
    }

    function test_owner_forwards() public {
        _initFixture();
        // The Member's `owner()` forwards to `IERC173(cluster).owner()`,
        // which on the diamond resolves through SolidStateDiamond's
        // pre-registered SafeOwnable. setUp's deployer is the test
        // contract, so `member.owner() == address(this)`.
        assertEq(member.owner(), IERC173(address(diamond)).owner(), "owner matches diamond");
        assertEq(member.owner(), address(this), "owner is deployer");
    }

    function test_version_forwardsToRuntimeAdapterVersion() public {
        _initFixture();
        // DstackAttestationAdapterFacet.dstack_version() returns 1.
        assertEq(member.version(), 1, "version forwards to dstack adapter");
        assertEq(
            member.version(),
            IDstackAttestationAdapter(address(diamond)).dstack_version(),
            "matches dstack adapter directly"
        );
    }

    // ─── Lifecycle view forwarders (3 tests) ───────────────────────────────

    function test_destroyedAt_forwards_returns0OnLiveCluster_thenTimestampOnDestroy() public {
        _initFixture();
        assertEq(member.destroyedAt(), 0, "live cluster");
        // destroy() requires the diamond's SafeOwnable owner (deployer).
        IAdmin(address(diamond)).destroy();
        assertEq(member.destroyedAt(), block.timestamp, "destroyed at now");
    }

    function test_destroyed_forwards() public {
        _initFixture();
        assertFalse(member.destroyed(), "alive");
        IAdmin(address(diamond)).destroy();
        assertTrue(member.destroyed(), "destroyed");
    }

    function test_memberRetiredAt_forwards() public {
        _initFixture();
        // AdminFacet.retireMember requires the id to exist in
        // CoreStorage.members[] (i.e., post-CoreFacet.register). Without
        // running register (which needs a real KMS sig chain), we can't
        // exercise the post-retire path here. So this test asserts the
        // forwarder simply returns 0 for an unknown id, proving the call
        // routes through ViewFacet.memberRetiredAt and reads the
        // LifecycleStorage mapping correctly.
        assertEq(member.memberRetiredAt(bytes32(uint256(0xDEADBEEF))), 0, "unretired returns 0");
    }

    // ─── Member-impl identity (1 test) ─────────────────────────────────────

    function test_memberImplVersion_returns1() public {
        _initFixture();
        assertEq(member.memberImplVersion(), 1, "v1 impl marker");
    }

    // ─── supportsInterface (2 tests) ───────────────────────────────────────

    function test_supportsInterface_returnsTrueForExpectedIds() public {
        _initFixture();
        assertTrue(member.supportsInterface(type(IAppAuth).interfaceId), "IAppAuth");
        assertTrue(member.supportsInterface(type(IAppAuthBasicManagement).interfaceId), "IAppAuthBasicManagement");
        assertTrue(member.supportsInterface(type(IERC165).interfaceId), "IERC165");
    }

    function test_supportsInterface_returnsFalseForOtherIds() public {
        _initFixture();
        bytes4 bogus = bytes4(keccak256("notAnInterface()"));
        assertFalse(member.supportsInterface(bogus), "bogus id rejected");
        // Sanity: an arbitrary non-zero selector that is not on the list.
        assertFalse(member.supportsInterface(0xdeadbeef), "deadbeef rejected");
    }

    // ─── UUPS upgrade authorization (5 tests) ──────────────────────────────

    function test_upgradeToAndCall_succeedsForClusterOwner_andSwapsBehavior() public {
        _initFixture();
        DstackMemberV2 v2Impl = new DstackMemberV2();

        // Caller is the deployer (= cluster owner); empty calldata path
        // (no post-upgrade init call required).
        UUPSUpgradeable(address(member)).upgradeToAndCall(address(v2Impl), "");

        // Behavior swap: v2's overridden version returns 2.
        assertEq(DstackMemberV2(address(member)).memberImplVersion(), 2, "upgraded to v2");

        // Storage continuity: cluster pointer is unchanged (same ERC-7201
        // namespace across v1 + v2), so reads still resolve to the diamond.
        assertEq(DstackMemberV2(address(member)).cluster(), address(diamond), "cluster preserved");

        // EIP-1967 implementation slot now points to v2.
        bytes32 implSlot = vm.load(address(member), EIP1967_IMPL_SLOT);
        assertEq(address(uint160(uint256(implSlot))), address(v2Impl), "impl slot points at v2");
    }

    function test_upgradeToAndCall_revertsForNonOwner() public {
        _initFixture();
        DstackMemberV2 v2Impl = new DstackMemberV2();
        vm.prank(nonOwner);
        vm.expectRevert(DstackMember.NotClusterOwner.selector);
        UUPSUpgradeable(address(member)).upgradeToAndCall(address(v2Impl), "");
    }

    function test_upgradeToAndCall_revertsAfterClusterDestroyed() public {
        _initFixture();
        DstackMemberV2 v2Impl = new DstackMemberV2();
        IAdmin(address(diamond)).destroy();

        // Even the legitimate cluster owner is blocked once the cluster's
        // `destroyedAt != 0`. Spec §7.4.
        vm.expectRevert(DstackMember.ClusterDestroyed_.selector);
        UUPSUpgradeable(address(member)).upgradeToAndCall(address(v2Impl), "");
    }

    function test_upgradeToAndCall_propagatesPostUpgradeBehavior() public {
        _initFixture();
        DstackMemberV2 v2Impl = new DstackMemberV2();
        UUPSUpgradeable(address(member)).upgradeToAndCall(address(v2Impl), "");

        // The v2 impl introduces a new selector (`pinged()`) that does not
        // exist on v1. If the proxy is dispatching to v2, this returns
        // true; if it's still on v1, the call would revert (no fallback,
        // unrecognized function selector).
        DstackMemberV2 m = DstackMemberV2(address(member));
        assertTrue(m.pinged(), "v2 selector callable through proxy");
    }

    function test_upgradeToAndCall_ownershipRotationPropagates() public {
        _initFixture();
        DstackMemberV2 v2Impl = new DstackMemberV2();

        // Rotate the diamond's SolidStateDiamond owner: deployer →
        // newOwner. SafeOwnable's two-step: nominate then accept.
        address newOwner = address(0xC0FFEE);
        IERC173(address(diamond)).transferOwnership(newOwner);
        // SafeOwnable's `acceptOwnership()` is not on IERC173; call it via
        // low-level call so the only-nominee modifier sees msg.sender =
        // newOwner.
        vm.prank(newOwner);
        (bool ok,) = address(diamond).call(abi.encodeWithSignature("acceptOwnership()"));
        require(ok, "acceptOwnership failed");

        // OLD owner (the test contract) must now be rejected. The Member's
        // `_authorizeUpgrade` reads `cluster.owner()` at call time, so this
        // should propagate without any per-Member action.
        vm.expectRevert(DstackMember.NotClusterOwner.selector);
        UUPSUpgradeable(address(member)).upgradeToAndCall(address(v2Impl), "");

        // NEW owner succeeds.
        vm.prank(newOwner);
        UUPSUpgradeable(address(member)).upgradeToAndCall(address(v2Impl), "");
        assertEq(DstackMemberV2(address(member)).memberImplVersion(), 2, "v2 active under new owner");
    }

    // ─── EIP-1967 storage slot identity (1 test) ───────────────────────────

    function test_implementationSlot_pointsToDstackMemberV1_thenV2OnUpgrade() public {
        _initFixture();
        bytes32 slotPre = vm.load(address(member), EIP1967_IMPL_SLOT);
        assertEq(address(uint160(uint256(slotPre))), address(dstackMemberImpl), "EIP-1967 slot starts on v1 impl");

        DstackMemberV2 v2Impl = new DstackMemberV2();
        UUPSUpgradeable(address(member)).upgradeToAndCall(address(v2Impl), "");

        bytes32 slotPost = vm.load(address(member), EIP1967_IMPL_SLOT);
        assertEq(address(uint160(uint256(slotPost))), address(v2Impl), "EIP-1967 slot moved to v2 impl");
    }
}

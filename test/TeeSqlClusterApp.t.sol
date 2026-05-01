// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {TeeSqlClusterApp} from "../src/TeeSqlClusterApp.sol";
import {TeeSqlClusterMember} from "../src/TeeSqlClusterMember.sol";
import {IAppAuth} from "../src/IAppAuth.sol";
import {IAppAuthBasicManagement} from "../src/IAppAuthBasicManagement.sol";
import {DstackSigChain} from "../src/DstackSigChain.sol";

/// @dev Harness exposes internal storage writers so we can seed a member without
///      requiring a full dstack 3-level sig chain. End-to-end sig-chain coverage is an
///      integration test, matching the existing DstackVerifier.t.sol pattern.
contract TeeSqlClusterAppHarness is TeeSqlClusterApp {
    function __testSetMember(
        bytes32 memberId,
        address instanceId,
        bytes memory derivedPubkey,
        address derivedAddr,
        address passthrough,
        bytes memory endpoint,
        bytes memory publicEndpoint
    ) external {
        ClusterStorage storage $ = _$();
        $.members[memberId] = Member({
            instanceId: instanceId,
            derivedPubkey: derivedPubkey,
            derivedAddr: derivedAddr,
            passthrough: passthrough,
            endpoint: endpoint,
            registeredAt: block.timestamp,
            publicEndpoint: publicEndpoint,
            dnsLabel: ""
        });
        $.instanceToMember[instanceId] = memberId;
        $.derivedToMember[derivedAddr] = memberId;
    }

    function __testSetPassthrough(address p, bool v) external {
        _$().isOurPassthrough[p] = v;
    }

    /// @dev Mirrors the side-effect set of prod `register()` for the
    ///      passthroughToMember mapping, so harness-seeded members
    ///      can also be looked up via the new view in tests.
    function __testSetPassthroughToMember(address p, bytes32 memberId) external {
        _$().passthroughToMember[p] = memberId;
    }
}

/// @dev Minimal mock of DstackKms exposing only what createMember needs.
contract MockDstackKms {
    mapping(address => bool) public registeredApps;
    bool public shouldRevert;

    function registerApp(address appId) external {
        require(!shouldRevert, "mock-revert");
        require(appId != address(0), "Invalid app ID");
        registeredApps[appId] = true;
    }

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }
}

contract TeeSqlClusterAppTest is Test {
    TeeSqlClusterAppHarness app;
    MockDstackKms mockKms;

    address constant OWNER = address(0xA11CE);
    address constant PAUSER = address(0xB0B);
    address constant ALICE = address(0xA11C);
    address constant BOB = address(0xB0B2);

    address kmsRootA = makeAddr("kmsRootA");

    // Member A
    uint256 aPk;
    address aAddr;
    bytes aPubkey33;
    bytes32 aMemberId;
    address aInstanceId;

    // Member B
    uint256 bPk;
    address bAddr;
    bytes bPubkey33;
    bytes32 bMemberId;
    address bInstanceId;

    // Member C (third node for witness-quorum tests)
    uint256 cPk;
    address cAddr;
    bytes cPubkey33;
    bytes32 cMemberId;
    address cInstanceId;

    address passthroughA;
    address passthroughB;
    address passthroughC;

    bytes32 constant COMPOSE_HASH = bytes32(uint256(0xC0DE));
    bytes32 constant DEVICE_ID = bytes32(uint256(0xDEEF));

    function setUp() public {
        mockKms = new MockDstackKms();

        TeeSqlClusterAppHarness impl = new TeeSqlClusterAppHarness();
        address[] memory roots = new address[](1);
        roots[0] = kmsRootA;
        bytes memory initData =
            abi.encodeCall(TeeSqlClusterApp.initialize, (OWNER, PAUSER, address(mockKms), "monitor", roots));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        app = TeeSqlClusterAppHarness(address(proxy));

        passthroughA = makeAddr("passthroughA");
        passthroughB = makeAddr("passthroughB");
        passthroughC = makeAddr("passthroughC");
        app.__testSetPassthrough(passthroughA, true);
        app.__testSetPassthrough(passthroughB, true);
        app.__testSetPassthrough(passthroughC, true);

        vm.startPrank(OWNER);
        app.addComposeHash(COMPOSE_HASH);
        app.addDevice(DEVICE_ID);
        vm.stopPrank();

        (aAddr, aPk) = makeAddrAndKey("memberA-derived");
        (bAddr, bPk) = makeAddrAndKey("memberB-derived");
        (cAddr, cPk) = makeAddrAndKey("memberC-derived");
        aPubkey33 = _fakePubkey(aAddr);
        bPubkey33 = _fakePubkey(bAddr);
        cPubkey33 = _fakePubkey(cAddr);
        aMemberId = keccak256(aPubkey33);
        bMemberId = keccak256(bPubkey33);
        cMemberId = keccak256(cPubkey33);
        aInstanceId = makeAddr("instA");
        bInstanceId = makeAddr("instB");
        cInstanceId = makeAddr("instC");

        app.__testSetMember(
            aMemberId, aInstanceId, aPubkey33, aAddr, passthroughA, "endpointA", "https://a.example"
        );
        app.__testSetMember(
            bMemberId, bInstanceId, bPubkey33, bAddr, passthroughB, "endpointB", "https://b.example"
        );
        app.__testSetMember(
            cMemberId, cInstanceId, cPubkey33, cAddr, passthroughC, "endpointC", "https://c.example"
        );
    }

    function _fakePubkey(address a) internal pure returns (bytes memory) {
        return bytes.concat(bytes1(0x02), bytes20(a), bytes12(0));
    }

    // --- Init + interfaces ---

    function test_initStoresConfig() public view {
        assertEq(app.owner(), OWNER);
        assertEq(app.pauser(), PAUSER);
        assertEq(app.kms(), address(mockKms));
        assertEq(app.clusterId(), "monitor");
        assertTrue(app.allowedKmsRoots(kmsRootA));
    }

    function test_initRejectsZeroArgs() public {
        TeeSqlClusterAppHarness impl = new TeeSqlClusterAppHarness();
        address[] memory roots = new address[](0);
        vm.expectRevert(TeeSqlClusterApp.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(TeeSqlClusterApp.initialize, (address(0), PAUSER, address(mockKms), "x", roots))
        );
        vm.expectRevert(TeeSqlClusterApp.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(TeeSqlClusterApp.initialize, (OWNER, address(0), address(mockKms), "x", roots))
        );
        vm.expectRevert(TeeSqlClusterApp.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl), abi.encodeCall(TeeSqlClusterApp.initialize, (OWNER, PAUSER, address(0), "x", roots))
        );
    }

    function test_supportsInterface() public view {
        assertTrue(app.supportsInterface(type(IAppAuth).interfaceId));
        assertTrue(app.supportsInterface(type(IAppAuthBasicManagement).interfaceId));
        assertTrue(app.supportsInterface(0x01ffc9a7));
        assertFalse(app.supportsInterface(0xdeadbeef));
    }

    function test_version() public view {
        // Bump in lockstep with every impl upgrade. CI test acts as a
        // forgotten-bump tripwire: change the impl, you must change this.
        // v2 adds destroy() / retireMember() / passthroughToMember.
        assertEq(app.version(), uint256(2));
    }

    // --- ERC-7201 storage layout sanity ---

    function test_storageLocationMatchesERC7201Derivation() public view {
        bytes32 expected = keccak256(abi.encode(uint256(keccak256("teesql.storage.ClusterApp")) - 1))
            & ~bytes32(uint256(0xff));
        assertEq(app.STORAGE_LOCATION(), expected);
    }

    function test_reinitializePlaceholderRevertsInV1() public {
        vm.expectRevert(bytes("TeeSqlClusterApp: no reinitializer for this version"));
        app.reinitialize(2, "");
    }

    function test_clusterStorageActuallyAtNamespacedSlot() public view {
        // ClusterStorage field offsets (declaration order, all 1-slot each):
        //   0: clusterId             1: allowedComposeHashes  2: allowedDeviceIds
        //   3: allowAnyDevice        4: allowedKmsRoots       5: members
        //   6: instanceToMember      7: derivedToMember       8: memberNonce
        //   9: onboarding           10: authorizedSigners    11: leaderMemberId
        //  12: leaderEpoch          13: isOurPassthrough     14: kms
        //  15: nextMemberSeq        16: pauser
        //
        // Verify by reading two fields whose values were set in setUp via initialize.
        bytes32 base = app.STORAGE_LOCATION();
        bytes32 kmsRaw = vm.load(address(app), bytes32(uint256(base) + 14));
        bytes32 pauserRaw = vm.load(address(app), bytes32(uint256(base) + 16));
        assertEq(address(uint160(uint256(kmsRaw))), address(mockKms));
        assertEq(address(uint160(uint256(pauserRaw))), PAUSER);
    }

    // --- createMember / predictMember ---

    function test_createMemberDeploysAndRegisters() public {
        bytes32 salt = keccak256("m1");
        address predicted = app.predictMember(salt);

        vm.recordLogs();
        address passthrough = app.createMember(salt);

        assertEq(passthrough, predicted, "predicted addr matches");
        assertTrue(app.isOurPassthrough(passthrough));
        assertTrue(mockKms.registeredApps(passthrough));
        assertEq(TeeSqlClusterMember(passthrough).cluster(), address(app));
    }

    function test_createMemberAutoSaltIncrements() public {
        address p0 = app.createMember(bytes32(0));
        address p1 = app.createMember(bytes32(0));
        assertTrue(p0 != p1);
        assertTrue(app.isOurPassthrough(p0));
        assertTrue(app.isOurPassthrough(p1));
        assertEq(app.nextMemberSeq(), 2);
    }

    function test_createMemberRevertsWhenPaused() public {
        vm.prank(PAUSER);
        app.pause();
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        app.createMember(bytes32("s"));
    }

    function test_createMemberPropagatesKmsRevert() public {
        mockKms.setShouldRevert(true);
        vm.expectRevert(bytes("mock-revert"));
        app.createMember(bytes32("s"));
    }

    // --- Passthrough contract itself ---

    function test_passthroughForwardsIsAppAllowed() public {
        address passthrough = app.createMember(bytes32("p"));
        IAppAuth.AppBootInfo memory b = _bootInfo(passthrough, COMPOSE_HASH, DEVICE_ID);
        (bool ok, string memory reason) = TeeSqlClusterMember(passthrough).isAppAllowed(b);
        assertTrue(ok, reason);
    }

    function test_passthroughRejectsWhenClusterPaused() public {
        address passthrough = app.createMember(bytes32("p"));
        vm.prank(PAUSER);
        app.pause();
        IAppAuth.AppBootInfo memory b = _bootInfo(passthrough, COMPOSE_HASH, DEVICE_ID);
        (bool ok, string memory reason) = TeeSqlClusterMember(passthrough).isAppAllowed(b);
        assertFalse(ok);
        assertEq(reason, "cluster paused");
    }

    function test_passthroughSupportsInterface() public {
        address passthrough = app.createMember(bytes32("p"));
        TeeSqlClusterMember m = TeeSqlClusterMember(passthrough);
        assertTrue(m.supportsInterface(type(IAppAuth).interfaceId));
        assertTrue(m.supportsInterface(0x01ffc9a7));
        assertFalse(m.supportsInterface(0xdeadbeef));
    }

    function test_passthroughConstructorRejectsZeroCluster() public {
        vm.expectRevert(TeeSqlClusterMember.ClusterZero.selector);
        new TeeSqlClusterMember(address(0));
    }

    function test_passthroughOwnerForwardsToCluster() public {
        address passthrough = app.createMember(bytes32("p-owner"));
        // Cluster owner is `OWNER` (set in setUp via __Ownable_init).
        assertEq(TeeSqlClusterMember(passthrough).owner(), OWNER);

        // Transfer cluster ownership using Ownable2Step's two-step flow,
        // then confirm the passthrough's owner() tracks it (read-only
        // forward, no caching).
        address NEW_OWNER = makeAddr("new-owner");
        vm.prank(OWNER);
        app.transferOwnership(NEW_OWNER);

        // After transferOwnership, ownership has NOT changed yet.
        assertEq(app.owner(), OWNER);
        assertEq(app.pendingOwner(), NEW_OWNER);
        assertEq(TeeSqlClusterMember(passthrough).owner(), OWNER);

        // The pending owner accepts.
        vm.prank(NEW_OWNER);
        app.acceptOwnership();
        assertEq(app.owner(), NEW_OWNER);
        assertEq(app.pendingOwner(), address(0));
        assertEq(TeeSqlClusterMember(passthrough).owner(), NEW_OWNER);
    }

    function test_acceptOwnershipRejectsNonPending() public {
        address NEW_OWNER = makeAddr("new-owner-2");
        address INTRUDER = makeAddr("intruder");

        vm.prank(OWNER);
        app.transferOwnership(NEW_OWNER);

        // A random address can't claim — even though the slot is "open".
        vm.prank(INTRUDER);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, INTRUDER));
        app.acceptOwnership();

        // The OLD owner can't accept their own pending tx either.
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, OWNER));
        app.acceptOwnership();

        // Pending state is unchanged after the rejected attempts.
        assertEq(app.owner(), OWNER);
        assertEq(app.pendingOwner(), NEW_OWNER);
    }

    function test_passthroughAllowlistGettersForwardToCluster() public {
        address passthrough = app.createMember(bytes32("p-allowlist"));
        TeeSqlClusterMember m = TeeSqlClusterMember(passthrough);

        // Cluster has COMPOSE_HASH + DEVICE_ID added in setUp().
        assertTrue(m.allowedComposeHashes(COMPOSE_HASH));
        assertTrue(m.allowedDeviceIds(DEVICE_ID));
        assertFalse(m.allowedComposeHashes(bytes32(uint256(0xBAD))));
        assertFalse(m.allowedDeviceIds(bytes32(uint256(0xBAD))));
        assertFalse(m.allowAnyDevice());

        // Mutate the cluster's allowlist + allowAnyDevice flag, observe
        // that the passthrough's reads track without caching.
        bytes32 NEW_HASH = bytes32(uint256(0xC0DE2));
        bytes32 NEW_DEV = bytes32(uint256(0xDEEF2));
        vm.startPrank(OWNER);
        app.addComposeHash(NEW_HASH);
        app.addDevice(NEW_DEV);
        app.setAllowAnyDevice(true);
        vm.stopPrank();

        assertTrue(m.allowedComposeHashes(NEW_HASH));
        assertTrue(m.allowedDeviceIds(NEW_DEV));
        assertTrue(m.allowAnyDevice());
    }

    function test_passthroughAdvertisesBasicManagementInterface() public {
        address passthrough = app.createMember(bytes32("p-iface"));
        TeeSqlClusterMember m = TeeSqlClusterMember(passthrough);
        // IAppAuth (0x1e079198), IAppAuthBasicManagement (0x8fd37527),
        // and IERC165 (0x01ffc9a7) all surface; arbitrary id stays false.
        assertTrue(m.supportsInterface(type(IAppAuth).interfaceId));
        assertTrue(m.supportsInterface(type(IAppAuthBasicManagement).interfaceId));
        assertTrue(m.supportsInterface(0x01ffc9a7));
        assertFalse(m.supportsInterface(0xdeadbeef));
    }

    function test_passthroughMutatorsForwardWhenCallerIsClusterOwner() public {
        address passthrough = app.createMember(bytes32("p-mutator"));
        TeeSqlClusterMember m = TeeSqlClusterMember(passthrough);

        bytes32 H = bytes32(uint256(0xC0DE3));
        bytes32 D = bytes32(uint256(0xDEEF3));

        // Cluster owner calls member.addComposeHash → forwards to cluster
        // → the cluster's isOurPassthrough[member] check accepts it.
        vm.prank(OWNER);
        m.addComposeHash(H);
        assertTrue(app.allowedComposeHashes(H));

        vm.prank(OWNER);
        m.addDevice(D);
        assertTrue(app.allowedDeviceIds(D));

        vm.prank(OWNER);
        m.removeComposeHash(H);
        assertFalse(app.allowedComposeHashes(H));

        vm.prank(OWNER);
        m.removeDevice(D);
        assertFalse(app.allowedDeviceIds(D));
    }

    function test_passthroughMutatorsRejectNonOwnerCaller() public {
        address passthrough = app.createMember(bytes32("p-mutator-rj"));
        TeeSqlClusterMember m = TeeSqlClusterMember(passthrough);

        // ALICE is not the cluster owner — member-level gate fires first.
        vm.prank(ALICE);
        vm.expectRevert(TeeSqlClusterMember.NotClusterOwner.selector);
        m.addComposeHash(bytes32(uint256(0xBAD)));

        vm.prank(ALICE);
        vm.expectRevert(TeeSqlClusterMember.NotClusterOwner.selector);
        m.addDevice(bytes32(uint256(0xBAD)));
    }

    // --- isAppAllowed gate ---

    function test_isAppAllowedPassesOnValidBoot() public view {
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, COMPOSE_HASH, DEVICE_ID);
        (bool ok, string memory reason) = app.isAppAllowed(b);
        assertTrue(ok, reason);
    }

    function test_isAppAllowedRejectsUnknownPassthrough() public {
        IAppAuth.AppBootInfo memory b = _bootInfo(makeAddr("rogue"), COMPOSE_HASH, DEVICE_ID);
        (bool ok, string memory reason) = app.isAppAllowed(b);
        assertFalse(ok);
        assertEq(reason, "unknown passthrough");
    }

    function test_isAppAllowedRejectsBadComposeHash() public view {
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, bytes32(uint256(0xBAD)), DEVICE_ID);
        (bool ok, string memory reason) = app.isAppAllowed(b);
        assertFalse(ok);
        assertEq(reason, "compose hash not allowed");
    }

    function test_isAppAllowedRejectsBadDeviceId() public view {
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, COMPOSE_HASH, bytes32(uint256(0xBAD)));
        (bool ok, string memory reason) = app.isAppAllowed(b);
        assertFalse(ok);
        assertEq(reason, "device not allowed");
    }

    function test_isAppAllowedSkipsDeviceCheckWhenAllowAny() public {
        vm.prank(OWNER);
        app.setAllowAnyDevice(true);
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, COMPOSE_HASH, bytes32(uint256(0xBAD)));
        (bool ok,) = app.isAppAllowed(b);
        assertTrue(ok);
    }

    function test_isAppAllowedFailsWhenPaused() public {
        vm.prank(PAUSER);
        app.pause();
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, COMPOSE_HASH, DEVICE_ID);
        (bool ok, string memory reason) = app.isAppAllowed(b);
        assertFalse(ok);
        assertEq(reason, "cluster paused");
    }

    // --- requireTcbUpToDate gate ---

    function test_requireTcbUpToDateDefaultsFalseAndSkipsTcbCheck() public view {
        // Default state: gate disabled, any tcbStatus accepted (matches v1
        // behavior on already-deployed clusters that haven't opted in).
        assertFalse(app.requireTcbUpToDate());
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, COMPOSE_HASH, DEVICE_ID);
        b.tcbStatus = "OutOfDate";
        (bool ok,) = app.isAppAllowed(b);
        assertTrue(ok);
    }

    function test_requireTcbUpToDateAcceptsUpToDateBoot() public {
        vm.prank(OWNER);
        app.setRequireTcbUpToDate(true);
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, COMPOSE_HASH, DEVICE_ID);
        b.tcbStatus = "UpToDate";
        (bool ok, string memory reason) = app.isAppAllowed(b);
        assertTrue(ok, reason);
    }

    function test_requireTcbUpToDateRejectsOutOfDateBoot() public {
        vm.prank(OWNER);
        app.setRequireTcbUpToDate(true);
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, COMPOSE_HASH, DEVICE_ID);
        b.tcbStatus = "OutOfDate";
        (bool ok, string memory reason) = app.isAppAllowed(b);
        assertFalse(ok);
        assertEq(reason, "tcb not up to date");
    }

    function test_requireTcbUpToDateRejectsEmptyTcbStatus() public {
        vm.prank(OWNER);
        app.setRequireTcbUpToDate(true);
        // Empty string is the default in `_bootInfo`; gate must reject when
        // the KMS hasn't populated tcbStatus rather than silently passing.
        IAppAuth.AppBootInfo memory b = _bootInfo(passthroughA, COMPOSE_HASH, DEVICE_ID);
        (bool ok, string memory reason) = app.isAppAllowed(b);
        assertFalse(ok);
        assertEq(reason, "tcb not up to date");
    }

    function test_setRequireTcbUpToDateOnlyOwnerOrPassthrough() public {
        vm.prank(ALICE);
        vm.expectRevert(TeeSqlClusterApp.NotAuthorized.selector);
        app.setRequireTcbUpToDate(true);

        vm.prank(OWNER);
        app.setRequireTcbUpToDate(true);
        assertTrue(app.requireTcbUpToDate());

        vm.prank(OWNER);
        app.setRequireTcbUpToDate(false);
        assertFalse(app.requireTcbUpToDate());
    }

    function test_passthroughForwardsSetRequireTcbUpToDate() public {
        address passthrough = app.createMember(bytes32("p-tcb"));
        TeeSqlClusterMember m = TeeSqlClusterMember(passthrough);

        // Non-owner caller is gated by the member's own check.
        vm.prank(ALICE);
        vm.expectRevert(TeeSqlClusterMember.NotClusterOwner.selector);
        m.setRequireTcbUpToDate(true);

        // Cluster owner calls through the member; the cluster's
        // _onlyOwnerOrPassthrough accepts the registered passthrough.
        vm.prank(OWNER);
        m.setRequireTcbUpToDate(true);
        assertTrue(app.requireTcbUpToDate());
        assertTrue(m.requireTcbUpToDate());
    }

    function test_passthroughForwardsSetAllowAnyDevice() public {
        address passthrough = app.createMember(bytes32("p-allowany"));
        TeeSqlClusterMember m = TeeSqlClusterMember(passthrough);

        vm.prank(ALICE);
        vm.expectRevert(TeeSqlClusterMember.NotClusterOwner.selector);
        m.setAllowAnyDevice(true);

        vm.prank(OWNER);
        m.setAllowAnyDevice(true);
        assertTrue(app.allowAnyDevice());
        assertTrue(m.allowAnyDevice());
    }

    // --- claimLeader (first claim + self-reclaim) ---

    function test_firstClaimNoWitnessRequired() public {
        bytes memory endpoint = hex"0102030405";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint, witnesses));

        app.claimLeader(auth, endpoint, witnesses);

        (bytes32 leaderId, uint256 epoch) = app.leaderLease();
        assertEq(leaderId, aMemberId);
        assertEq(epoch, 1);
        assertEq(app.memberNonce(aMemberId), 1);
    }

    function test_selfReclaimNoWitnessRequired() public {
        bytes memory ep1 = hex"aa";
        bytes memory ep2 = hex"bb";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);

        TeeSqlClusterApp.CallAuth memory auth1 =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(ep1, witnesses));
        app.claimLeader(auth1, ep1, witnesses);

        // Same member reclaims — no witnesses required; epoch bumps.
        TeeSqlClusterApp.CallAuth memory auth2 =
            _makeCallAuth(aMemberId, aPk, 1, app.claimLeader.selector, abi.encode(ep2, witnesses));
        app.claimLeader(auth2, ep2, witnesses);

        (bytes32 leaderId, uint256 epoch) = app.leaderLease();
        assertEq(leaderId, aMemberId);
        assertEq(epoch, 2);
    }

    function test_claimLeaderRejectsReplay() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint, witnesses));
        app.claimLeader(auth, endpoint, witnesses);

        vm.expectRevert(TeeSqlClusterApp.BadNonce.selector);
        app.claimLeader(auth, endpoint, witnesses);
    }

    function test_claimLeaderRejectsWrongSigner() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        // Sign with B's key but claim to be A
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, bPk, 0, app.claimLeader.selector, abi.encode(endpoint, witnesses));
        vm.expectRevert(TeeSqlClusterApp.BadSig.selector);
        app.claimLeader(auth, endpoint, witnesses);
    }

    // --- claimLeader witness-based takeover ---

    function test_takeoverRequiresWitness() public {
        // A claims first
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");

        // B tries to take over with empty witnesses — rejected.
        bytes memory ep = hex"bb";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        vm.expectRevert(TeeSqlClusterApp.NoWitness.selector);
        app.claimLeader(bAuth, ep, witnesses);
    }

    function test_takeoverSucceedsWithWitnessFromOtherMember() public {
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        (bytes32 leaderId0, uint256 epoch0) = app.leaderLease();

        // B claims, witnessed by C.
        bytes memory ep = hex"bb";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](1);
        witnesses[0] = _makeWitness(leaderId0, epoch0, cMemberId, cPk);

        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        app.claimLeader(bAuth, ep, witnesses);

        (bytes32 leaderId, uint256 epoch) = app.leaderLease();
        assertEq(leaderId, bMemberId);
        assertEq(epoch, epoch0 + 1);
    }

    function test_selfWitnessRejected() public {
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        (bytes32 leaderId0, uint256 epoch0) = app.leaderLease();

        // B claims but provides a witness from itself (claimant == voucher).
        bytes memory ep = hex"bb";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](1);
        witnesses[0] = _makeWitness(leaderId0, epoch0, bMemberId, bPk);

        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        vm.expectRevert(TeeSqlClusterApp.SelfWitness.selector);
        app.claimLeader(bAuth, ep, witnesses);
    }

    function test_duplicateWitnessRejected() public {
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        (bytes32 leaderId0, uint256 epoch0) = app.leaderLease();

        bytes memory ep = hex"bb";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](2);
        witnesses[0] = _makeWitness(leaderId0, epoch0, cMemberId, cPk);
        witnesses[1] = _makeWitness(leaderId0, epoch0, cMemberId, cPk);

        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        vm.expectRevert(TeeSqlClusterApp.DuplicateWitness.selector);
        app.claimLeader(bAuth, ep, witnesses);
    }

    function test_witnessFromNonMemberRejected() public {
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        (bytes32 leaderId0, uint256 epoch0) = app.leaderLease();

        // Sign a witness with a random key + a bogus voucherMemberId.
        bytes32 bogusId = keccak256("not-a-member");
        (, uint256 randPk) = makeAddrAndKey("rand");
        bytes memory ep = hex"bb";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](1);
        witnesses[0] = _makeWitness(leaderId0, epoch0, bogusId, randPk);

        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        vm.expectRevert(TeeSqlClusterApp.WitnessNotMember.selector);
        app.claimLeader(bAuth, ep, witnesses);
    }

    function test_witnessWithBadSigRejected() public {
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        (bytes32 leaderId0, uint256 epoch0) = app.leaderLease();

        // Voucher is C (a valid member) but signed by the wrong key (aPk).
        bytes memory ep = hex"bb";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](1);
        witnesses[0] = _makeWitness(leaderId0, epoch0, cMemberId, aPk);

        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        vm.expectRevert(TeeSqlClusterApp.BadWitnessSig.selector);
        app.claimLeader(bAuth, ep, witnesses);
    }

    function test_crossEpochWitnessReplayRejected() public {
        // Epoch 1: A claims.
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        (bytes32 leaderId1, uint256 epoch1) = app.leaderLease();

        // C signs a valid witness for epoch 1.
        TeeSqlClusterApp.Witness memory epoch1Witness = _makeWitness(leaderId1, epoch1, cMemberId, cPk);

        // B takes over at epoch 2 using C's witness.
        {
            bytes memory ep = hex"bb";
            TeeSqlClusterApp.Witness[] memory ws = new TeeSqlClusterApp.Witness[](1);
            ws[0] = epoch1Witness;
            TeeSqlClusterApp.CallAuth memory bAuth =
                _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, ws));
            app.claimLeader(bAuth, ep, ws);
        }
        (, uint256 epoch2) = app.leaderLease();
        assertEq(epoch2, epoch1 + 1);

        // Now A tries to take over at epoch 2 replaying C's original epoch-1 witness.
        // Should fail: witness message binds to (B, epoch2), not (A, epoch1).
        {
            bytes memory ep = hex"cc";
            TeeSqlClusterApp.Witness[] memory ws = new TeeSqlClusterApp.Witness[](1);
            ws[0] = epoch1Witness;
            TeeSqlClusterApp.CallAuth memory aAuth =
                _makeCallAuth(aMemberId, aPk, 1, app.claimLeader.selector, abi.encode(ep, ws));
            vm.expectRevert(TeeSqlClusterApp.BadWitnessSig.selector);
            app.claimLeader(aAuth, ep, ws);
        }
    }

    // --- currentLeader ---

    function test_currentLeaderRevertsBeforeClaim() public {
        vm.expectRevert(TeeSqlClusterApp.NotLeaderClaimant.selector);
        app.currentLeader();
    }

    function test_currentLeaderReturnsLatestAfterClaim() public {
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        TeeSqlClusterApp.Member memory m = app.currentLeader();
        assertEq(m.instanceId, aInstanceId);
        assertEq(m.endpoint, hex"aa");
    }

    // --- updateEndpoint / updatePublicEndpoint ---

    function test_updateEndpointStoresAndEmits() public {
        bytes memory ep = hex"cafebabe";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.updateEndpoint.selector, abi.encode(ep));

        vm.expectEmit(true, false, false, true, address(app));
        emit TeeSqlClusterApp.EndpointUpdated(aMemberId, ep);
        app.updateEndpoint(auth, ep);

        TeeSqlClusterApp.Member memory m = app.getMember(aMemberId);
        assertEq(m.endpoint, ep);
    }

    function test_updatePublicEndpointStoresAndEmits() public {
        bytes memory url = bytes("https://new.example");
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.updatePublicEndpoint.selector, abi.encode(url));

        vm.expectEmit(true, false, false, true, address(app));
        emit TeeSqlClusterApp.PublicEndpointUpdated(aMemberId, url);
        app.updatePublicEndpoint(auth, url);

        TeeSqlClusterApp.Member memory m = app.getMember(aMemberId);
        assertEq(m.publicEndpoint, url);
    }

    function test_updateEndpointFromNonMemberReverts() public {
        bytes32 bogusId = keccak256("bogus");
        bytes memory ep = hex"aa";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(bogusId, aPk, 0, app.updateEndpoint.selector, abi.encode(ep));
        vm.expectRevert(TeeSqlClusterApp.NotMember.selector);
        app.updateEndpoint(auth, ep);
    }

    // --- CallAuth scope pinning ---

    function test_callSigBoundToContractAddress() public {
        TeeSqlClusterAppHarness impl2 = new TeeSqlClusterAppHarness();
        address[] memory roots = new address[](1);
        roots[0] = kmsRootA;
        bytes memory initData =
            abi.encodeCall(TeeSqlClusterApp.initialize, (OWNER, PAUSER, address(mockKms), "other", roots));
        ERC1967Proxy proxy2 = new ERC1967Proxy(address(impl2), initData);
        TeeSqlClusterAppHarness app2 = TeeSqlClusterAppHarness(address(proxy2));
        app2.__testSetPassthrough(passthroughA, true);
        app2.__testSetMember(
            aMemberId, aInstanceId, aPubkey33, aAddr, passthroughA, "endpointA", "https://a.example"
        );

        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint, witnesses));

        vm.expectRevert(TeeSqlClusterApp.BadSig.selector);
        app2.claimLeader(auth, endpoint, witnesses);
    }

    function test_callSigBoundToSelector() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        // Sign for updateEndpoint, submit as claimLeader.
        TeeSqlClusterApp.CallAuth memory sig =
            _makeCallAuth(aMemberId, aPk, 0, app.updateEndpoint.selector, abi.encode(endpoint));
        vm.expectRevert(TeeSqlClusterApp.BadSig.selector);
        app.claimLeader(sig, endpoint, witnesses);
    }

    function test_callSigBoundToArgs() public {
        bytes memory signedEndpoint = hex"aa";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(signedEndpoint, witnesses));
        vm.expectRevert(TeeSqlClusterApp.BadSig.selector);
        app.claimLeader(auth, hex"bb", witnesses);
    }

    function test_callFromNonMemberReverts() public {
        bytes32 bogusId = keccak256("bogus");
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(bogusId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint, witnesses));
        vm.expectRevert(TeeSqlClusterApp.NotMember.selector);
        app.claimLeader(auth, endpoint, witnesses);
    }

    // --- Onboarding ---

    function test_onboardPostsMessage() public {
        bytes memory payload = hex"deadbeef";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.onboard.selector, abi.encode(bMemberId, payload));
        app.onboard(auth, bMemberId, payload);

        TeeSqlClusterApp.OnboardMsg[] memory msgs = app.getOnboarding(bMemberId);
        assertEq(msgs.length, 1);
        assertEq(msgs[0].fromMember, aMemberId);
        assertEq(msgs[0].encryptedPayload, payload);
    }

    function test_onboardRequiresRecipientExists() public {
        bytes32 missing = keccak256("nobody");
        bytes memory payload = hex"deadbeef";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.onboard.selector, abi.encode(missing, payload));
        vm.expectRevert(TeeSqlClusterApp.NotMember.selector);
        app.onboard(auth, missing, payload);
    }

    // --- Pause ---

    function test_pauserCanPauseOwnerCanUnpause() public {
        vm.prank(PAUSER);
        app.pause();
        assertTrue(app.paused());

        // Pauser can NOT unpause — that's owner-only.
        vm.prank(PAUSER);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, PAUSER));
        app.unpause();

        vm.prank(OWNER);
        app.unpause();
        assertFalse(app.paused());
    }

    function test_nonPauserCannotPause() public {
        vm.expectRevert(TeeSqlClusterApp.NotAuthorized.selector);
        app.pause();
    }

    function test_setPauserOnlyOwnerAndUpdates() public {
        address newPauser = makeAddr("newPauser");

        // Non-owner can't rotate.
        vm.prank(PAUSER);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, PAUSER));
        app.setPauser(newPauser);

        // Owner can.
        vm.prank(OWNER);
        app.setPauser(newPauser);
        assertEq(app.pauser(), newPauser);

        // Old pauser loses the power.
        vm.prank(PAUSER);
        vm.expectRevert(TeeSqlClusterApp.NotAuthorized.selector);
        app.pause();

        // New pauser holds it.
        vm.prank(newPauser);
        app.pause();
        assertTrue(app.paused());
    }

    function test_pauseBlocksAuthenticatedCalls() public {
        vm.prank(PAUSER);
        app.pause();

        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint, witnesses));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        app.claimLeader(auth, endpoint, witnesses);

        TeeSqlClusterApp.CallAuth memory upAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.updateEndpoint.selector, abi.encode(endpoint));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        app.updateEndpoint(upAuth, endpoint);
    }

    // --- Admin ---

    function test_onlyOwnerOrPassthroughCanMutateAllowlists() public {
        // Test caller is neither the owner nor a registered passthrough,
        // so addComposeHash now reverts with NotAuthorized() (the unified
        // error from the new gate; previously it was OZ
        // OwnableUnauthorizedAccount because addComposeHash was onlyOwner).
        vm.expectRevert(TeeSqlClusterApp.NotAuthorized.selector);
        app.addComposeHash(bytes32(uint256(1)));

        vm.prank(OWNER);
        app.addComposeHash(bytes32(uint256(1)));
        assertTrue(app.allowedComposeHashes(bytes32(uint256(1))));

        // A registered passthrough is also allowed (the path phala-cli
        // takes when forwarding `addComposeHash` through the member).
        vm.prank(passthroughA);
        app.addComposeHash(bytes32(uint256(2)));
        assertTrue(app.allowedComposeHashes(bytes32(uint256(2))));

        // An unrelated contract address is NOT allowed even if it has
        // a value in `isOurPassthrough` set to false.
        address rogue = makeAddr("rogue-passthrough");
        vm.prank(rogue);
        vm.expectRevert(TeeSqlClusterApp.NotAuthorized.selector);
        app.addComposeHash(bytes32(uint256(3)));
    }

    function test_authorizeAndRevokeSigner() public {
        vm.prank(OWNER);
        app.authorizeSigner(ALICE, 3);
        assertTrue(app.isSignerAuthorized(ALICE, 1));
        assertTrue(app.isSignerAuthorized(ALICE, 2));
        assertTrue(app.isSignerAuthorized(ALICE, 3));

        vm.prank(OWNER);
        app.revokeSigner(ALICE);
        assertFalse(app.isSignerAuthorized(ALICE, 1));
    }

    function test_authorizeSignerRejectsZeroAndBadPerms() public {
        vm.startPrank(OWNER);
        vm.expectRevert(TeeSqlClusterApp.ZeroAddress.selector);
        app.authorizeSigner(address(0), 1);
        vm.expectRevert(TeeSqlClusterApp.BadPerms.selector);
        app.authorizeSigner(ALICE, 0);
        vm.expectRevert(TeeSqlClusterApp.BadPerms.selector);
        app.authorizeSigner(ALICE, 4);
        vm.stopPrank();
    }

    function test_setKmsRejectsZero() public {
        vm.prank(OWNER);
        vm.expectRevert(TeeSqlClusterApp.ZeroAddress.selector);
        app.setKms(address(0));
    }

    function test_upgradeRequiresOwner() public {
        TeeSqlClusterAppHarness v2 = new TeeSqlClusterAppHarness();
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        app.upgradeToAndCall(address(v2), "");

        vm.prank(OWNER);
        app.upgradeToAndCall(address(v2), "");
    }

    // --- Lifecycle: destroy ---

    function test_destroyOnlyOwner() public {
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        app.destroy();

        // Pauser is a different role and must not be able to destroy.
        vm.prank(PAUSER);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, PAUSER));
        app.destroy();

        vm.prank(OWNER);
        vm.expectEmit(false, false, false, true, address(app));
        emit TeeSqlClusterApp.ClusterDestroyed(block.timestamp);
        app.destroy();
        assertTrue(app.destroyed());
        assertEq(app.destroyedAt(), block.timestamp);
    }

    function test_destroyIsIdempotentRevert() public {
        vm.startPrank(OWNER);
        app.destroy();
        // Second call reverts; the flag is one-way.
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.destroy();
        vm.stopPrank();
    }

    function test_isAppAllowedRejectsDestroyed() public {
        address passthrough = app.createMember(bytes32("p-destroyed"));
        IAppAuth.AppBootInfo memory b = _bootInfo(passthrough, COMPOSE_HASH, DEVICE_ID);
        // Pre-destroy: passes.
        (bool ok,) = app.isAppAllowed(b);
        assertTrue(ok);

        vm.prank(OWNER);
        app.destroy();

        (bool ok2, string memory reason) = app.isAppAllowed(b);
        assertFalse(ok2);
        assertEq(reason, "cluster destroyed");
    }

    function test_isAppAllowedDestroyedReasonWinsOverPause() public {
        address passthrough = app.createMember(bytes32("p-destroyed-paused"));
        IAppAuth.AppBootInfo memory b = _bootInfo(passthrough, COMPOSE_HASH, DEVICE_ID);

        vm.prank(PAUSER);
        app.pause();
        // Paused but not destroyed: pause wins.
        (, string memory pausedReason) = app.isAppAllowed(b);
        assertEq(pausedReason, "cluster paused");

        // Owner can still unpause -> destroy. Order matters because
        // `whenNotDestroyed` doesn't gate `unpause` (covered by the
        // owner-housekeeping carve-out).
        vm.startPrank(OWNER);
        app.unpause();
        app.destroy();
        vm.stopPrank();

        // Re-pause to confirm destroy wins regardless. Pauser is still
        // the pauser EOA — but `whenNotDestroyed` gate is on `setPauser`,
        // not `pause`, and `pause` itself isn't destroy-gated.
        vm.prank(PAUSER);
        app.pause();
        (bool ok, string memory destroyedReason) = app.isAppAllowed(b);
        assertFalse(ok);
        assertEq(destroyedReason, "cluster destroyed", "destroy reason wins");
    }

    function test_destroyBlocksOwnerOrPassthroughMutators() public {
        // Mint a passthrough so we have a non-owner authorized caller.
        address passthrough = app.createMember(bytes32("p-destroy-mut"));

        vm.prank(OWNER);
        app.destroy();

        bytes32 H = bytes32(uint256(0xC0DE99));
        bytes32 D = bytes32(uint256(0xDEEF99));

        // Owner gets the destroy revert before any other gate.
        vm.startPrank(OWNER);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.addComposeHash(H);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.removeComposeHash(H);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.addDevice(D);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.removeDevice(D);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.setAllowAnyDevice(true);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.setRequireTcbUpToDate(true);
        vm.stopPrank();

        // Same calls from a registered passthrough also revert with
        // ClusterDestroyed_ — the gate runs before the passthrough check.
        vm.startPrank(passthrough);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.addComposeHash(H);
        vm.stopPrank();
    }

    function test_destroyBlocksOwnerOnlyMutators() public {
        vm.prank(OWNER);
        app.destroy();

        address kmsRootB = makeAddr("kmsRootB");
        address newKms = makeAddr("newKms");
        address newPauser = makeAddr("newPauser-d");

        vm.startPrank(OWNER);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.addKmsRoot(kmsRootB);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.removeKmsRoot(kmsRootA);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.authorizeSigner(ALICE, 1);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.revokeSigner(ALICE);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.setKms(newKms);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.setPauser(newPauser);
        vm.stopPrank();
    }

    function test_destroyBlocksCallAuthMutators() public {
        // Pre-destroy: all four CallAuth mutators are reachable. We
        // exercise updateEndpoint as the canary; _verifyCall is the
        // shared chokepoint for claimLeader/updateEndpoint/
        // updatePublicEndpoint/onboard, so gating via `whenNotDestroyed`
        // on the mutator wraps the whole family.
        bytes memory ep = hex"abcd";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.updateEndpoint.selector, abi.encode(ep));

        vm.prank(OWNER);
        app.destroy();

        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.updateEndpoint(auth, ep);

        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory clAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.claimLeader(clAuth, ep, witnesses);

        bytes memory url = bytes("https://nope.example");
        TeeSqlClusterApp.CallAuth memory upAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.updatePublicEndpoint.selector, abi.encode(url));
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.updatePublicEndpoint(upAuth, url);

        bytes memory payload = hex"01";
        TeeSqlClusterApp.CallAuth memory obAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.onboard.selector, abi.encode(bMemberId, payload));
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.onboard(obAuth, bMemberId, payload);
    }

    function test_destroyAllowsOwnerHousekeeping() public {
        vm.prank(OWNER);
        app.destroy();

        address newOwner = makeAddr("post-destroy-new-owner");

        // transferOwnership / acceptOwnership remain callable.
        vm.prank(OWNER);
        app.transferOwnership(newOwner);
        assertEq(app.pendingOwner(), newOwner);
        vm.prank(newOwner);
        app.acceptOwnership();
        assertEq(app.owner(), newOwner);

        // Pause / unpause stay reachable too — they're transient state
        // and intentionally outside the destroy gate. (The spec calls
        // out `unpause`; we exercise both for symmetry.)
        vm.prank(PAUSER);
        app.pause();
        assertTrue(app.paused());
        vm.prank(newOwner);
        app.unpause();
        assertFalse(app.paused());
    }

    function test_destroyKeepsReadsLive() public {
        // Seed onboarding payload + claim leader pre-destroy so the
        // post-destroy reads have something interesting to return.
        _claimLeaderAs(aMemberId, aPk, 0, hex"aabb");
        bytes memory payload = hex"deadbeef";
        TeeSqlClusterApp.CallAuth memory obAuth =
            _makeCallAuth(aMemberId, aPk, 1, app.onboard.selector, abi.encode(bMemberId, payload));
        app.onboard(obAuth, bMemberId, payload);

        vm.prank(OWNER);
        app.destroy();

        // Forensic reads stay live post-destroy.
        assertEq(app.clusterId(), "monitor");
        assertTrue(app.allowedComposeHashes(COMPOSE_HASH));
        assertTrue(app.allowedDeviceIds(DEVICE_ID));
        assertEq(app.version(), uint256(2));
        TeeSqlClusterApp.Member memory m = app.getMember(aMemberId);
        assertEq(m.instanceId, aInstanceId);
        TeeSqlClusterApp.Member memory leader = app.currentLeader();
        assertEq(leader.instanceId, aInstanceId);
        (bytes32 leaderId, uint256 epoch) = app.leaderLease();
        assertEq(leaderId, aMemberId);
        assertEq(epoch, uint256(1));
        TeeSqlClusterApp.OnboardMsg[] memory onboarded = app.getOnboarding(bMemberId);
        assertEq(onboarded.length, uint256(1));
    }

    // --- Lifecycle: retireMember ---

    function test_retireOnlyOwner() public {
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        app.retireMember(aMemberId);

        vm.prank(PAUSER);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, PAUSER));
        app.retireMember(aMemberId);

        vm.prank(OWNER);
        vm.expectEmit(true, false, false, true, address(app));
        emit TeeSqlClusterApp.MemberRetired(aMemberId, block.timestamp);
        app.retireMember(aMemberId);
        assertEq(app.memberRetiredAt(aMemberId), block.timestamp);
    }

    function test_retireRevertsForUnknownMember() public {
        bytes32 ghost = keccak256("not-a-member");
        vm.prank(OWNER);
        vm.expectRevert(TeeSqlClusterApp.NotMember.selector);
        app.retireMember(ghost);
    }

    function test_retireRevertsIfAlreadyRetired() public {
        vm.startPrank(OWNER);
        app.retireMember(aMemberId);
        vm.expectRevert(TeeSqlClusterApp.AlreadyRetired.selector);
        app.retireMember(aMemberId);
        vm.stopPrank();
    }

    function test_retireRevertsForCurrentLeader() public {
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        vm.prank(OWNER);
        vm.expectRevert(TeeSqlClusterApp.CannotRetireLeader.selector);
        app.retireMember(aMemberId);

        // After a successor takes over, the previous leader can be retired.
        TeeSqlClusterApp.Witness[] memory ws = new TeeSqlClusterApp.Witness[](1);
        ws[0] = _makeWitness(aMemberId, uint256(1), cMemberId, cPk);
        bytes memory ep = hex"bb";
        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, ws));
        app.claimLeader(bAuth, ep, ws);

        vm.prank(OWNER);
        app.retireMember(aMemberId);
        assertGt(app.memberRetiredAt(aMemberId), uint256(0));
    }

    function test_retiredMemberMutatorsRevert() public {
        vm.prank(OWNER);
        app.retireMember(aMemberId);

        // claimLeader from a retired member — even when the cluster is
        // leader-less so witness checks don't fire. _verifyCall trips
        // first.
        bytes memory ep = hex"aa";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory clAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        vm.expectRevert(TeeSqlClusterApp.MemberRetired_.selector);
        app.claimLeader(clAuth, ep, witnesses);

        TeeSqlClusterApp.CallAuth memory upAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.updateEndpoint.selector, abi.encode(ep));
        vm.expectRevert(TeeSqlClusterApp.MemberRetired_.selector);
        app.updateEndpoint(upAuth, ep);

        bytes memory url = bytes("https://retired.example");
        TeeSqlClusterApp.CallAuth memory pubAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.updatePublicEndpoint.selector, abi.encode(url));
        vm.expectRevert(TeeSqlClusterApp.MemberRetired_.selector);
        app.updatePublicEndpoint(pubAuth, url);

        bytes memory payload = hex"01";
        TeeSqlClusterApp.CallAuth memory obAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.onboard.selector, abi.encode(bMemberId, payload));
        vm.expectRevert(TeeSqlClusterApp.MemberRetired_.selector);
        app.onboard(obAuth, bMemberId, payload);
    }

    function test_retiredMemberReadsStillWork() public {
        vm.prank(OWNER);
        app.retireMember(aMemberId);

        // Member row remains readable; only the lifecycle flag changes.
        TeeSqlClusterApp.Member memory m = app.getMember(aMemberId);
        assertEq(m.instanceId, aInstanceId);
        assertEq(m.passthrough, passthroughA);
        assertGt(app.memberRetiredAt(aMemberId), uint256(0));
        assertEq(app.memberRetiredAt(bMemberId), uint256(0));
    }

    function test_retireDoesNotAffectOtherMembers() public {
        vm.prank(OWNER);
        app.retireMember(aMemberId);

        // B is unaffected — claimLeader, updateEndpoint, etc. all work.
        _claimLeaderAs(bMemberId, bPk, 0, hex"bb");
        (bytes32 leaderId,) = app.leaderLease();
        assertEq(leaderId, bMemberId);

        bytes memory ep = hex"cccc";
        TeeSqlClusterApp.CallAuth memory upAuth =
            _makeCallAuth(bMemberId, bPk, 1, app.updateEndpoint.selector, abi.encode(ep));
        app.updateEndpoint(upAuth, ep);
        TeeSqlClusterApp.Member memory bRow = app.getMember(bMemberId);
        assertEq(bRow.endpoint, ep);
    }

    function test_destroyAndRetireCombined() public {
        // Retire one member, destroy the cluster — both events should
        // fire and both flags persist for forensic queries.
        vm.startPrank(OWNER);
        app.retireMember(aMemberId);
        vm.expectEmit(false, false, false, true, address(app));
        emit TeeSqlClusterApp.ClusterDestroyed(block.timestamp);
        app.destroy();
        vm.stopPrank();

        assertGt(app.memberRetiredAt(aMemberId), uint256(0));
        assertTrue(app.destroyed());
        // Trying to retire another member after destroy must hit the
        // destroy gate (whenNotDestroyed) before NotMember/AlreadyRetired.
        vm.prank(OWNER);
        vm.expectRevert(TeeSqlClusterApp.ClusterDestroyed_.selector);
        app.retireMember(bMemberId);
    }

    // --- Lifecycle: passthroughToMember lookup ---

    function test_passthroughToMemberLookup() public {
        // Existing harness-seeded members have been written via
        // __testSetMember which doesn't populate passthroughToMember
        // (the prod write is in `register()`). Verify post-`register`
        // population by minting a new passthrough and registering.
        // The harness exposes a writer for that scenario directly:
        // we backfill via __testSetMember + manual storage.
        //
        // For the canonical path, spin up a fresh cluster + use the
        // sigchain mock — but that's the integration test's job.
        // Here we exercise the view directly: zero before write, set
        // after `register()`.
        assertEq(app.passthroughToMember(passthroughA), bytes32(0));

        // Use the harness to simulate a register() write:
        // passthroughToMember is now part of the register() side-effect
        // set, so the harness writer is updated to match.
        app.__testSetPassthroughToMember(passthroughA, aMemberId);
        assertEq(app.passthroughToMember(passthroughA), aMemberId);
        assertEq(app.passthroughToMember(makeAddr("nobody")), bytes32(0));
    }

    // --- TeeSqlClusterMember view passthroughs ---

    function test_memberDestroyViewPassthroughs() public {
        address passthrough = app.createMember(bytes32("p-life"));
        TeeSqlClusterMember m = TeeSqlClusterMember(passthrough);

        assertFalse(m.destroyed());
        assertEq(m.destroyedAt(), uint256(0));
        assertEq(m.memberRetiredAt(aMemberId), uint256(0));

        vm.startPrank(OWNER);
        app.retireMember(aMemberId);
        app.destroy();
        vm.stopPrank();

        assertTrue(m.destroyed());
        assertEq(m.destroyedAt(), block.timestamp);
        assertEq(m.memberRetiredAt(aMemberId), block.timestamp);
        // Non-retired member still reads zero.
        assertEq(m.memberRetiredAt(bMemberId), uint256(0));
    }

    // --- Helpers ---

    function _bootInfo(address appId, bytes32 composeHash, bytes32 deviceId)
        internal
        pure
        returns (IAppAuth.AppBootInfo memory)
    {
        string[] memory empty = new string[](0);
        return IAppAuth.AppBootInfo({
            appId: appId,
            composeHash: composeHash,
            instanceId: address(0),
            deviceId: deviceId,
            mrAggregated: bytes32(0),
            mrSystem: bytes32(0),
            osImageHash: bytes32(0),
            tcbStatus: "",
            advisoryIds: empty
        });
    }

    function _makeCallAuth(bytes32 memberId, uint256 pk, uint256 nonce, bytes4 selector, bytes memory args)
        internal
        view
        returns (TeeSqlClusterApp.CallAuth memory)
    {
        bytes32 h = app.callMessage(memberId, nonce, selector, args);
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return TeeSqlClusterApp.CallAuth({memberId: memberId, nonce: nonce, sig: abi.encodePacked(r, s, v)});
    }

    function _makeWitness(bytes32 deposedMemberId, uint256 deposedEpoch, bytes32 voucherMemberId, uint256 voucherPk)
        internal
        view
        returns (TeeSqlClusterApp.Witness memory)
    {
        bytes32 wMsg = app.witnessMessage(deposedMemberId, deposedEpoch, voucherMemberId);
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", wMsg));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(voucherPk, ethHash);
        return TeeSqlClusterApp.Witness({voucherMemberId: voucherMemberId, sig: abi.encodePacked(r, s, v)});
    }

    function _claimLeaderAs(bytes32 memberId, uint256 pk, uint256 nonce, bytes memory endpoint) internal {
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(memberId, pk, nonce, app.claimLeader.selector, abi.encode(endpoint, witnesses));
        app.claimLeader(auth, endpoint, witnesses);
    }
}

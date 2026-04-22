// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

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
        string memory role,
        bytes memory endpoint,
        bytes memory publicEndpoint
    ) external {
        _members[memberId] = Member({
            instanceId: instanceId,
            derivedPubkey: derivedPubkey,
            derivedAddr: derivedAddr,
            passthrough: passthrough,
            role: role,
            endpoint: endpoint,
            registeredAt: block.timestamp,
            __deprecated_lastHeartbeat: 0,
            publicEndpoint: publicEndpoint
        });
        instanceToMember[instanceId] = memberId;
        derivedToMember[derivedAddr] = memberId;
    }

    function __testSetPassthrough(address p, bool v) external {
        isOurPassthrough[p] = v;
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
            aMemberId, aInstanceId, aPubkey33, aAddr, passthroughA, "primary", "endpointA", "https://a.example"
        );
        app.__testSetMember(
            bMemberId, bInstanceId, bPubkey33, bAddr, passthroughB, "secondary", "endpointB", "https://b.example"
        );
        app.__testSetMember(
            cMemberId, cInstanceId, cPubkey33, cAddr, passthroughC, "secondary", "endpointC", "https://c.example"
        );
    }

    function _fakePubkey(address a) internal pure returns (bytes memory) {
        return bytes.concat(bytes1(0x02), bytes20(a), bytes12(0));
    }

    // --- Init + interfaces ---

    function test_initStoresConfig() public view {
        assertEq(app.owner(), OWNER);
        assertTrue(app.hasRole(app.PAUSER_ROLE(), PAUSER));
        assertTrue(app.hasRole(app.DEFAULT_ADMIN_ROLE(), OWNER));
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

    // --- claimLeader (first claim + self-reclaim) ---

    function test_firstClaimNoWitnessRequired() public {
        bytes memory endpoint = hex"0102030405";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](0);
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint, witnesses));

        app.claimLeader(auth, endpoint, witnesses);

        (bytes32 leaderId, uint256 epoch,) = app.leaderLease();
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

        (bytes32 leaderId, uint256 epoch,) = app.leaderLease();
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
        (bytes32 leaderId0, uint256 epoch0,) = app.leaderLease();

        // B claims, witnessed by C.
        bytes memory ep = hex"bb";
        TeeSqlClusterApp.Witness[] memory witnesses = new TeeSqlClusterApp.Witness[](1);
        witnesses[0] = _makeWitness(leaderId0, epoch0, cMemberId, cPk);

        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(ep, witnesses));
        app.claimLeader(bAuth, ep, witnesses);

        (bytes32 leaderId, uint256 epoch,) = app.leaderLease();
        assertEq(leaderId, bMemberId);
        assertEq(epoch, epoch0 + 1);
    }

    function test_selfWitnessRejected() public {
        _claimLeaderAs(aMemberId, aPk, 0, hex"aa");
        (bytes32 leaderId0, uint256 epoch0,) = app.leaderLease();

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
        (bytes32 leaderId0, uint256 epoch0,) = app.leaderLease();

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
        (bytes32 leaderId0, uint256 epoch0,) = app.leaderLease();

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
        (bytes32 leaderId0, uint256 epoch0,) = app.leaderLease();

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
        (bytes32 leaderId1, uint256 epoch1,) = app.leaderLease();

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
        (, uint256 epoch2,) = app.leaderLease();
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
            aMemberId, aInstanceId, aPubkey33, aAddr, passthroughA, "primary", "endpointA", "https://a.example"
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

    function test_pauserCanPauseAdminCanUnpause() public {
        bytes32 adminRole = app.DEFAULT_ADMIN_ROLE();
        vm.prank(PAUSER);
        app.pause();
        assertTrue(app.paused());

        bytes memory expected =
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, PAUSER, adminRole);
        vm.prank(PAUSER);
        vm.expectRevert(expected);
        app.unpause();

        vm.prank(OWNER);
        app.unpause();
        assertFalse(app.paused());
    }

    function test_nonPauserCannotPause() public {
        bytes32 pauserRole = app.PAUSER_ROLE();
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), pauserRole)
        );
        app.pause();
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

    function test_onlyOwnerCanMutateAllowlists() public {
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        app.addComposeHash(bytes32(uint256(1)));

        vm.prank(OWNER);
        app.addComposeHash(bytes32(uint256(1)));
        assertTrue(app.allowedComposeHashes(bytes32(uint256(1))));
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

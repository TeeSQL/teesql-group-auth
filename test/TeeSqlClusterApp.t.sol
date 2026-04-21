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
        bytes memory endpoint
    ) external {
        _members[memberId] = Member({
            instanceId: instanceId,
            derivedPubkey: derivedPubkey,
            derivedAddr: derivedAddr,
            passthrough: passthrough,
            role: role,
            endpoint: endpoint,
            registeredAt: block.timestamp,
            lastHeartbeat: block.timestamp
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
    bytes aPubkey33; // placeholder 33-byte pubkey (not used by CallAuth logic)
    bytes32 aMemberId;
    address aInstanceId;

    // Member B
    uint256 bPk;
    address bAddr;
    bytes bPubkey33;
    bytes32 bMemberId;
    address bInstanceId;

    // Two synthetic passthroughs
    address passthroughA;
    address passthroughB;

    // Compose + device baseline
    bytes32 constant COMPOSE_HASH = bytes32(uint256(0xC0DE));
    bytes32 constant DEVICE_ID = bytes32(uint256(0xDEEF));

    function setUp() public {
        mockKms = new MockDstackKms();

        TeeSqlClusterAppHarness impl = new TeeSqlClusterAppHarness();
        address[] memory roots = new address[](1);
        roots[0] = kmsRootA;
        bytes memory initData =
            abi.encodeCall(TeeSqlClusterApp.initialize, (OWNER, PAUSER, address(mockKms), "monitor", 60, roots));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        app = TeeSqlClusterAppHarness(address(proxy));

        // Seed two passthroughs without going through createMember (not testing that here)
        passthroughA = makeAddr("passthroughA");
        passthroughB = makeAddr("passthroughB");
        app.__testSetPassthrough(passthroughA, true);
        app.__testSetPassthrough(passthroughB, true);

        // Seed default compose + device
        vm.startPrank(OWNER);
        app.addComposeHash(COMPOSE_HASH);
        app.addDevice(DEVICE_ID);
        vm.stopPrank();

        // Derive signing keys + seed members
        (aAddr, aPk) = makeAddrAndKey("memberA-derived");
        (bAddr, bPk) = makeAddrAndKey("memberB-derived");
        aPubkey33 = _fakePubkey(aAddr);
        bPubkey33 = _fakePubkey(bAddr);
        aMemberId = keccak256(aPubkey33);
        bMemberId = keccak256(bPubkey33);
        aInstanceId = makeAddr("instA");
        bInstanceId = makeAddr("instB");

        app.__testSetMember(aMemberId, aInstanceId, aPubkey33, aAddr, passthroughA, "primary", "endpointA");
        app.__testSetMember(bMemberId, bInstanceId, bPubkey33, bAddr, passthroughB, "secondary", "endpointB");
    }

    function _fakePubkey(address a) internal pure returns (bytes memory) {
        // 33-byte marker derived from address. Irrelevant for CallAuth tests since
        // _verifyCall compares against derivedAddr, which the harness sets directly.
        return bytes.concat(bytes1(0x02), bytes20(a), bytes12(0));
    }

    // --- Init + interfaces ---

    function test_initStoresConfig() public view {
        assertEq(app.owner(), OWNER);
        assertTrue(app.hasRole(app.PAUSER_ROLE(), PAUSER));
        assertTrue(app.hasRole(app.DEFAULT_ADMIN_ROLE(), OWNER));
        assertEq(app.kms(), address(mockKms));
        assertEq(app.leaseTTL(), 60);
        assertEq(app.clusterId(), "monitor");
        assertTrue(app.allowedKmsRoots(kmsRootA));
    }

    function test_initRejectsZeroArgs() public {
        TeeSqlClusterAppHarness impl = new TeeSqlClusterAppHarness();
        address[] memory roots = new address[](0);
        vm.expectRevert(TeeSqlClusterApp.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(TeeSqlClusterApp.initialize, (address(0), PAUSER, address(mockKms), "x", 60, roots))
        );
        vm.expectRevert(TeeSqlClusterApp.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl),
            abi.encodeCall(TeeSqlClusterApp.initialize, (OWNER, address(0), address(mockKms), "x", 60, roots))
        );
        vm.expectRevert(TeeSqlClusterApp.ZeroAddress.selector);
        new ERC1967Proxy(
            address(impl), abi.encodeCall(TeeSqlClusterApp.initialize, (OWNER, PAUSER, address(0), "x", 60, roots))
        );
    }

    function test_supportsInterface() public view {
        assertTrue(app.supportsInterface(type(IAppAuth).interfaceId));
        assertTrue(app.supportsInterface(type(IAppAuthBasicManagement).interfaceId));
        assertTrue(app.supportsInterface(0x01ffc9a7)); // IERC165
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

    // --- CallAuth / claimLeader / heartbeat ---

    function test_claimLeaderSucceedsWithValidSig() public {
        bytes memory endpoint = hex"0102030405";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));

        app.claimLeader(auth, endpoint);

        (bytes32 leaderId, uint256 epoch, uint256 expiresAt) = app.leaderLease();
        assertEq(leaderId, aMemberId);
        assertEq(epoch, 1);
        assertEq(expiresAt, block.timestamp + 60);
        assertEq(app.memberNonce(aMemberId), 1);
    }

    function test_claimLeaderRejectsReplay() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        app.claimLeader(auth, endpoint);

        vm.expectRevert(TeeSqlClusterApp.BadNonce.selector);
        app.claimLeader(auth, endpoint);
    }

    function test_claimLeaderRejectsWrongSigner() public {
        bytes memory endpoint = hex"aa";
        // Sign with B's key but claim to be A
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, bPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        vm.expectRevert(TeeSqlClusterApp.BadSig.selector);
        app.claimLeader(auth, endpoint);
    }

    function test_claimLeaderBlockedByActiveLease() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory aAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        app.claimLeader(aAuth, endpoint);

        // B tries to claim while A's lease is still active
        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        vm.expectRevert(TeeSqlClusterApp.LeaseActive.selector);
        app.claimLeader(bAuth, endpoint);
    }

    function test_claimLeaderAllowsTakeoverAfterExpiry() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory aAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        app.claimLeader(aAuth, endpoint);

        // Fast-forward past lease expiry
        vm.warp(block.timestamp + 61);

        TeeSqlClusterApp.CallAuth memory bAuth =
            _makeCallAuth(bMemberId, bPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        app.claimLeader(bAuth, endpoint);

        (bytes32 leaderId, uint256 epoch,) = app.leaderLease();
        assertEq(leaderId, bMemberId);
        assertEq(epoch, 2);
    }

    function test_heartbeatExtendsLease() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory aAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        app.claimLeader(aAuth, endpoint);
        uint256 t0 = block.timestamp;

        vm.warp(t0 + 30);

        TeeSqlClusterApp.CallAuth memory hbAuth = _makeCallAuth(aMemberId, aPk, 1, app.heartbeat.selector, "");
        app.heartbeat(hbAuth);

        (,, uint256 expiresAt) = app.leaderLease();
        assertEq(expiresAt, t0 + 30 + 60);
    }

    function test_heartbeatFromNonLeaderDoesNotExtendLease() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory aAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        app.claimLeader(aAuth, endpoint);
        (,, uint256 expiresBefore) = app.leaderLease();

        vm.warp(block.timestamp + 10);

        // B heartbeats — valid call, but B isn't leader, so lease unchanged
        TeeSqlClusterApp.CallAuth memory hbAuth = _makeCallAuth(bMemberId, bPk, 0, app.heartbeat.selector, "");
        app.heartbeat(hbAuth);

        (,, uint256 expiresAfter) = app.leaderLease();
        assertEq(expiresAfter, expiresBefore);
    }

    function test_currentLeaderRevertsBeforeClaim() public {
        vm.expectRevert(TeeSqlClusterApp.NotLeaderClaimant.selector);
        app.currentLeader();
    }

    function test_currentLeaderRevertsAfterExpiry() public {
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory aAuth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        app.claimLeader(aAuth, endpoint);
        vm.warp(block.timestamp + 61);
        vm.expectRevert(TeeSqlClusterApp.NotLeaderClaimant.selector);
        app.currentLeader();
    }

    // --- CallAuth scope pinning ---

    function test_callSigBoundToContractAddress() public {
        // Deploy a second cluster app and try to reuse sig
        TeeSqlClusterAppHarness impl2 = new TeeSqlClusterAppHarness();
        address[] memory roots = new address[](1);
        roots[0] = kmsRootA;
        bytes memory initData =
            abi.encodeCall(TeeSqlClusterApp.initialize, (OWNER, PAUSER, address(mockKms), "other", 60, roots));
        ERC1967Proxy proxy2 = new ERC1967Proxy(address(impl2), initData);
        TeeSqlClusterAppHarness app2 = TeeSqlClusterAppHarness(address(proxy2));
        // Seed same member in app2
        app2.__testSetPassthrough(passthroughA, true);
        app2.__testSetMember(aMemberId, aInstanceId, aPubkey33, aAddr, passthroughA, "primary", "endpointA");

        // Sig produced for app1
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));

        // Submit to app2 — should fail BadSig (address(this) differs)
        vm.expectRevert(TeeSqlClusterApp.BadSig.selector);
        app2.claimLeader(auth, endpoint);
    }

    function test_callSigBoundToSelector() public {
        // Sign a heartbeat sig, try to use it as claimLeader
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory hbSig = _makeCallAuth(aMemberId, aPk, 0, app.heartbeat.selector, "");
        vm.expectRevert(TeeSqlClusterApp.BadSig.selector);
        app.claimLeader(hbSig, endpoint);
    }

    function test_callSigBoundToArgs() public {
        // Sig produced for endpoint "aa", submit with endpoint "bb"
        bytes memory signedEndpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(signedEndpoint));
        vm.expectRevert(TeeSqlClusterApp.BadSig.selector);
        app.claimLeader(auth, hex"bb");
    }

    function test_callFromNonMemberReverts() public {
        bytes32 bogusId = keccak256("bogus");
        bytes memory endpoint = hex"aa";
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(bogusId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        vm.expectRevert(TeeSqlClusterApp.NotMember.selector);
        app.claimLeader(auth, endpoint);
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

    // --- Pause semantics ---

    function test_pauserCanPauseAdminCanUnpause() public {
        bytes32 adminRole = app.DEFAULT_ADMIN_ROLE();
        vm.prank(PAUSER);
        app.pause();
        assertTrue(app.paused());

        // PAUSER cannot unpause
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
        TeeSqlClusterApp.CallAuth memory auth =
            _makeCallAuth(aMemberId, aPk, 0, app.claimLeader.selector, abi.encode(endpoint));
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        app.claimLeader(auth, endpoint);

        TeeSqlClusterApp.CallAuth memory hbAuth = _makeCallAuth(aMemberId, aPk, 0, app.heartbeat.selector, "");
        vm.expectRevert(PausableUpgradeable.EnforcedPause.selector);
        app.heartbeat(hbAuth);
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
}

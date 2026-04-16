// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {IVerifier} from "../src/IVerifier.sol";
import {TEEBridge} from "../src/TEEBridge.sol";

/// @dev Mock verifier that accepts whatever codeId / pubkey / userData the
///      test sets via `setReturn(...)`, skipping any real cryptographic work.
///      This lets us test TEEBridge's membership + onboarding logic
///      independent of the dstack sig chain.
contract MockVerifier is IVerifier {
    bytes32 public retCodeId;
    bytes public retPubkey;
    bytes public retUserData;
    bool public shouldRevert;

    function setReturn(bytes32 codeId, bytes calldata pubkey, bytes calldata userData) external {
        retCodeId = codeId;
        retPubkey = pubkey;
        retUserData = userData;
    }

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function verify(bytes calldata)
        external
        view
        override
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        require(!shouldRevert, "MOCK_REVERT");
        return (retCodeId, retPubkey, retUserData);
    }

    function verifyAndCache(bytes calldata proof)
        external
        override
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        return this.verify(proof);
    }
}

contract TEEBridgeTest is Test {
    TEEBridge bridge;
    MockVerifier verifier;
    address owner = address(0xA11CE);
    bytes32 constant ALLOWED_CODE = keccak256("teesql-xyn-compose");
    bytes PUBKEY_ALICE = hex"0278a9cbd96b9b8b8ba2e0d4c21fef6c9b1ae45d70f42b1a5f8a9c9b9e3f3b3b11";
    bytes PUBKEY_BOB   = hex"0378a9cbd96b9b8b8ba2e0d4c21fef6c9b1ae45d70f42b1a5f8a9c9b9e3f3b3b22";
    bytes32 MEMBER_ALICE;
    bytes32 MEMBER_BOB;

    function setUp() public {
        // Deploy verifier (no proxy needed for the mock)
        verifier = new MockVerifier();

        // Deploy bridge behind ERC1967 proxy
        TEEBridge impl = new TEEBridge();

        address[] memory verifiers = new address[](1);
        verifiers[0] = address(verifier);

        bytes32[] memory codes = new bytes32[](1);
        codes[0] = ALLOWED_CODE;

        bytes memory initData = abi.encodeCall(TEEBridge.initialize, (owner, verifiers, codes));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        bridge = TEEBridge(address(proxy));

        MEMBER_ALICE = keccak256(PUBKEY_ALICE);
        MEMBER_BOB = keccak256(PUBKEY_BOB);
    }

    // --- initialize ---

    function test_initializeSetsOwnerAndSeed() public view {
        assertEq(bridge.owner(), owner);
        assertTrue(bridge.allowedVerifiers(address(verifier)));
        assertTrue(bridge.allowedCode(ALLOWED_CODE));
    }

    function test_initializeRejectsZeroOwner() public {
        TEEBridge impl = new TEEBridge();
        address[] memory v = new address[](0);
        bytes32[] memory c = new bytes32[](0);
        bytes memory init = abi.encodeCall(TEEBridge.initialize, (address(0), v, c));
        vm.expectRevert(TEEBridge.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), init);
    }

    function test_initializeRejectsZeroVerifier() public {
        TEEBridge impl = new TEEBridge();
        address[] memory v = new address[](1);
        v[0] = address(0);
        bytes32[] memory c = new bytes32[](0);
        bytes memory init = abi.encodeCall(TEEBridge.initialize, (owner, v, c));
        vm.expectRevert(TEEBridge.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), init);
    }

    function test_cannotInitializeTwice() public {
        address[] memory v = new address[](0);
        bytes32[] memory c = new bytes32[](0);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        bridge.initialize(owner, v, c);
    }

    // --- admin: allowlists ---

    function test_onlyOwnerCanAddVerifier() public {
        address v = address(0xBEEF);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        bridge.addVerifier(v);

        vm.prank(owner);
        bridge.addVerifier(v);
        assertTrue(bridge.allowedVerifiers(v));
    }

    function test_ownerCanAddAndRemoveAllowedCode() public {
        bytes32 newCode = keccak256("another");
        vm.prank(owner);
        bridge.addAllowedCode(newCode);
        assertTrue(bridge.allowedCode(newCode));

        vm.prank(owner);
        bridge.removeAllowedCode(newCode);
        assertFalse(bridge.allowedCode(newCode));
    }

    function test_addVerifierRejectsZero() public {
        vm.prank(owner);
        vm.expectRevert(TEEBridge.ZeroAddress.selector);
        bridge.addVerifier(address(0));
    }

    // --- register ---

    function test_registerSuccess() public {
        verifier.setReturn(ALLOWED_CODE, PUBKEY_ALICE, "");
        bytes32 memberId = bridge.register(address(verifier), "");

        assertEq(memberId, MEMBER_ALICE);
        assertTrue(bridge.isMember(MEMBER_ALICE));

        (bytes32 codeId, address ver, bytes memory pk,, uint256 registeredAt) = bridge.getMember(MEMBER_ALICE);
        assertEq(codeId, ALLOWED_CODE);
        assertEq(ver, address(verifier));
        assertEq(pk, PUBKEY_ALICE);
        assertEq(registeredAt, block.timestamp);
    }

    function test_registerRevertsWithUnallowedVerifier() public {
        MockVerifier unallowed = new MockVerifier();
        unallowed.setReturn(ALLOWED_CODE, PUBKEY_ALICE, "");
        vm.expectRevert(TEEBridge.VerifierNotAllowed.selector);
        bridge.register(address(unallowed), "");
    }

    function test_registerRevertsWithUnallowedCode() public {
        verifier.setReturn(keccak256("nope"), PUBKEY_ALICE, "");
        vm.expectRevert(TEEBridge.CodeNotAllowed.selector);
        bridge.register(address(verifier), "");
    }

    function test_doubleRegisterReverts() public {
        verifier.setReturn(ALLOWED_CODE, PUBKEY_ALICE, "");
        bridge.register(address(verifier), "");

        verifier.setReturn(ALLOWED_CODE, PUBKEY_ALICE, "");
        vm.expectRevert(TEEBridge.AlreadyRegistered.selector);
        bridge.register(address(verifier), "");
    }

    // --- onboard ---

    function test_onboardStoresMessage() public {
        verifier.setReturn(ALLOWED_CODE, PUBKEY_ALICE, "");
        bridge.register(address(verifier), "");
        verifier.setReturn(ALLOWED_CODE, PUBKEY_BOB, "");
        bridge.register(address(verifier), "");

        bytes memory payload = hex"deadbeef";
        bridge.onboard(MEMBER_ALICE, MEMBER_BOB, payload);

        TEEBridge.OnboardMsg[] memory msgs = bridge.getOnboarding(MEMBER_BOB);
        assertEq(msgs.length, 1);
        assertEq(msgs[0].fromMember, MEMBER_ALICE);
        assertEq(msgs[0].encryptedPayload, payload);
    }

    function test_onboardFromUnknownMemberReverts() public {
        verifier.setReturn(ALLOWED_CODE, PUBKEY_BOB, "");
        bridge.register(address(verifier), "");

        vm.expectRevert(TEEBridge.MemberNotFound.selector);
        bridge.onboard(MEMBER_ALICE, MEMBER_BOB, hex"01");
    }

    function test_onboardToUnknownMemberReverts() public {
        verifier.setReturn(ALLOWED_CODE, PUBKEY_ALICE, "");
        bridge.register(address(verifier), "");

        vm.expectRevert(TEEBridge.MemberNotFound.selector);
        bridge.onboard(MEMBER_ALICE, MEMBER_BOB, hex"01");
    }

    // --- UUPS ---

    function test_nonOwnerCannotUpgrade() public {
        TEEBridge v2 = new TEEBridge();
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        bridge.upgradeToAndCall(address(v2), "");
    }

    function test_ownerCanUpgrade() public {
        TEEBridge v2 = new TEEBridge();
        vm.prank(owner);
        bridge.upgradeToAndCall(address(v2), "");
        // After upgrade, proxy still answers — owner preserved
        assertEq(bridge.owner(), owner);
    }
}

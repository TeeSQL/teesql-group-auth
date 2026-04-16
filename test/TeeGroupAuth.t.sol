// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TeeGroupAuth} from "../src/TeeGroupAuth.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @dev V2 stub for upgrade testing — adds a new view function, preserves storage layout
contract TeeGroupAuthV2 is TeeGroupAuth {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract TeeGroupAuthTest is Test {
    TeeGroupAuth tga;
    TeeGroupAuth implementation;
    ERC1967Proxy proxy;

    // Dstack key hierarchy
    uint256 kmsPriv = 0xA11CE;
    uint256 appPriv = 0xB0B;
    uint256 derivedPriv = 0xCA7;

    // Second KMS root for multi-root tests
    uint256 kmsPriv2 = 0xA11CF;

    bytes constant APP_PUBKEY = hex"035d45cb81aa765d69ca52e3869491ecf0e8fdf6a63d64e65b5213647ee4973ae5";
    bytes constant DERIVED_PUBKEY = hex"0203dffc4af6214b639839fbc2b949621a35ae41bbe7679eee5798afbe85919f69";

    address kmsRoot;
    address kmsRoot2;
    bytes32 appId = bytes32(bytes20(uint160(0xDEAD)));

    // Second dstack node keys for multi-member tests
    uint256 derivedPriv2 = 0xDA7A;
    bytes constant DERIVED_PUBKEY2 = hex"02ec4c96d7f444c25fbf83598f3bca0aae69a110303980d8826bb2fe33f7e3c105";

    address owner;

    function setUp() public {
        owner = address(this);
        kmsRoot = vm.addr(kmsPriv);
        kmsRoot2 = vm.addr(kmsPriv2);

        implementation = new TeeGroupAuth();

        address[] memory roots = new address[](1);
        roots[0] = kmsRoot;

        bytes32[] memory codes = new bytes32[](1);
        codes[0] = appId;

        bytes memory initData = abi.encodeCall(
            TeeGroupAuth.initialize,
            (owner, roots, codes)
        );

        proxy = new ERC1967Proxy(address(implementation), initData);
        tga = TeeGroupAuth(address(proxy));
    }

    // --- Helpers ---

    function _sign(uint256 privKey, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);
        return abi.encodePacked(r, s, v);
    }

    function _bytesToHex(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            str[i*2] = alphabet[uint8(data[i] >> 4)];
            str[i*2+1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    function _buildDstackProof(
        bytes32 messageHash,
        uint256 _kmsPriv,
        uint256 _appPriv,
        uint256 _derivedPriv,
        bytes memory _derivedPubkey,
        bytes memory _appPubkey,
        bytes32 _appId
    ) internal pure returns (TeeGroupAuth.DstackProof memory) {
        string memory derivedHex = _bytesToHex(_derivedPubkey);
        string memory appMessage = string(abi.encodePacked("ethereum:", derivedHex));
        bytes memory appSignature = _sign(_appPriv, keccak256(bytes(appMessage)));
        bytes memory kmsSignature = _sign(_kmsPriv, keccak256(abi.encodePacked("dstack-kms-issued:", bytes20(_appId), _appPubkey)));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        bytes memory messageSignature = _sign(_derivedPriv, ethHash);

        return TeeGroupAuth.DstackProof({
            messageHash: messageHash,
            messageSignature: messageSignature,
            appSignature: appSignature,
            kmsSignature: kmsSignature,
            derivedCompressedPubkey: _derivedPubkey,
            appCompressedPubkey: _appPubkey,
            purpose: "ethereum"
        });
    }

    function _buildDefaultDstackProof(bytes32 messageHash) internal view returns (TeeGroupAuth.DstackProof memory) {
        return _buildDstackProof(messageHash, kmsPriv, appPriv, derivedPriv, DERIVED_PUBKEY, APP_PUBKEY, appId);
    }

    function _registerDstack() internal returns (bytes32) {
        return tga.registerDstack(appId, _buildDefaultDstackProof(keccak256("handshake")));
    }

    function _derivedAddress() internal view returns (address) {
        // Compute the address from DERIVED_PUBKEY using the same logic the contract uses
        return vm.addr(derivedPriv);
    }

    function _derivedAddress2() internal view returns (address) {
        return vm.addr(derivedPriv2);
    }

    // --- Initialization ---

    function test_Initialization() public view {
        assertEq(tga.owner(), owner);
        assertTrue(tga.trustedKmsRoots(kmsRoot));
        assertTrue(tga.allowedCode(appId));
        assertEq(tga.secretVersion(), 1);
    }

    function test_InitializeRevertsOnReinitialization() public {
        address[] memory roots = new address[](0);
        bytes32[] memory codes = new bytes32[](0);
        vm.expectRevert();
        tga.initialize(owner, roots, codes);
    }

    function test_InitializeRevertsZeroAddressRoot() public {
        TeeGroupAuth impl2 = new TeeGroupAuth();
        address[] memory roots = new address[](1);
        roots[0] = address(0);
        bytes32[] memory codes = new bytes32[](0);

        bytes memory initData = abi.encodeCall(
            TeeGroupAuth.initialize,
            (owner, roots, codes)
        );

        vm.expectRevert(TeeGroupAuth.ZeroAddress.selector);
        new ERC1967Proxy(address(impl2), initData);
    }

    // --- Trusted KMS Roots ---

    function test_AddTrustedKmsRoot() public {
        address newRoot = address(0x1234);
        vm.expectEmit(true, false, false, false);
        emit TeeGroupAuth.TrustedKmsRootAdded(newRoot);
        tga.addTrustedKmsRoot(newRoot);
        assertTrue(tga.trustedKmsRoots(newRoot));
    }

    function test_AddTrustedKmsRootRevertsZeroAddress() public {
        vm.expectRevert(TeeGroupAuth.ZeroAddress.selector);
        tga.addTrustedKmsRoot(address(0));
    }

    function test_RemoveTrustedKmsRoot() public {
        vm.expectEmit(true, false, false, false);
        emit TeeGroupAuth.TrustedKmsRootRemoved(kmsRoot);
        tga.removeTrustedKmsRoot(kmsRoot);
        assertFalse(tga.trustedKmsRoots(kmsRoot));
    }

    function test_OnlyOwnerCanManageRoots() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.addTrustedKmsRoot(address(0x1234));

        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.removeTrustedKmsRoot(kmsRoot);
    }

    // --- Allowed Code Management ---

    function test_AddAllowedCode() public {
        bytes32 newCode = keccak256("new-code");
        vm.expectEmit(true, false, false, false);
        emit TeeGroupAuth.AllowedCodeAdded(newCode);
        tga.addAllowedCode(newCode);
        assertTrue(tga.allowedCode(newCode));
    }

    function test_RemoveAllowedCode() public {
        tga.removeAllowedCode(appId);
        assertFalse(tga.allowedCode(appId));
    }

    function test_OnlyOwnerCanManageCode() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.addAllowedCode(keccak256("x"));
    }

    // --- Dstack Registration ---

    function test_RegisterDstack() public {
        bytes32 memberId = _registerDstack();
        assertEq(memberId, keccak256(DERIVED_PUBKEY));
        assertTrue(tga.isMember(memberId));

        (bytes32 codeId, bytes memory pubkey, uint256 registeredAt) = tga.getMember(memberId);
        assertEq(codeId, appId);
        assertEq(pubkey, DERIVED_PUBKEY);
        assertGt(registeredAt, 0);
    }

    function test_RegisterDstack_EmitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit TeeGroupAuth.MemberRegistered(keccak256(DERIVED_PUBKEY), appId, DERIVED_PUBKEY);
        _registerDstack();
    }

    function test_RegisterDstack_RevertBadChain() public {
        bytes32 wrongAppId = bytes32(bytes20(uint160(0xBEEF)));
        tga.addAllowedCode(wrongAppId);
        vm.expectRevert(TeeGroupAuth.InvalidDstackSignature.selector);
        tga.registerDstack(wrongAppId, _buildDefaultDstackProof(keccak256("m")));
    }

    function test_RegisterDstack_RevertCodeNotAllowed() public {
        tga.removeAllowedCode(appId);
        vm.expectRevert(TeeGroupAuth.CodeNotAllowed.selector);
        tga.registerDstack(appId, _buildDefaultDstackProof(keccak256("m")));
    }

    function test_RegisterDstack_RevertDuplicate() public {
        _registerDstack();
        vm.expectRevert(TeeGroupAuth.AlreadyRegistered.selector);
        _registerDstack();
    }

    function test_RegisterDstack_UntrustedKmsRoot() public {
        // Remove the trusted root
        tga.removeTrustedKmsRoot(kmsRoot);
        vm.expectRevert(TeeGroupAuth.InvalidDstackSignature.selector);
        tga.registerDstack(appId, _buildDefaultDstackProof(keccak256("m")));
    }

    // --- Multi-root Registration ---

    function test_MultiRoot_RegisterFromTwoRoots() public {
        // Register first member via kmsRoot (already trusted)
        bytes32 memberId1 = _registerDstack();
        assertTrue(tga.isMember(memberId1));

        // Add second KMS root
        tga.addTrustedKmsRoot(kmsRoot2);

        // We need a second dstack node with different keys signed by kmsRoot2
        // Use derivedPriv2 and build proof with kmsPriv2
        // First we need the app pubkey for this second chain — use the same appPriv for simplicity
        TeeGroupAuth.DstackProof memory proof2 = _buildDstackProof(
            keccak256("handshake2"),
            kmsPriv2,          // second KMS root
            appPriv,           // same app key (different KMS issued it)
            derivedPriv2,      // different derived key
            DERIVED_PUBKEY2,
            APP_PUBKEY,
            appId
        );

        bytes32 memberId2 = tga.registerDstack(appId, proof2);
        assertTrue(tga.isMember(memberId2));
        assertTrue(memberId1 != memberId2);
    }

    // --- Member Revocation ---

    function test_RevokeMember() public {
        bytes32 memberId = _registerDstack();
        assertTrue(tga.isMember(memberId));

        vm.expectEmit(true, false, false, false);
        emit TeeGroupAuth.MemberRevoked(memberId);
        tga.revokeMember(memberId);

        assertFalse(tga.isMember(memberId));

        (bytes32 codeId, bytes memory pubkey, uint256 registeredAt) = tga.getMember(memberId);
        assertEq(codeId, bytes32(0));
        assertEq(pubkey.length, 0);
        assertEq(registeredAt, 0);
    }

    function test_RevokeMember_RevertNotFound() public {
        vm.expectRevert(TeeGroupAuth.MemberNotFound.selector);
        tga.revokeMember(keccak256("nobody"));
    }

    function test_RevokeMember_OnlyOwner() public {
        bytes32 memberId = _registerDstack();
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.revokeMember(memberId);
    }

    // --- Secret Versioning ---

    function test_SecretVersion_StartsAtOne() public view {
        assertEq(tga.secretVersion(), 1);
    }

    function test_RotateSecret() public {
        vm.expectEmit(false, false, false, true);
        emit TeeGroupAuth.SecretRotated(2);
        tga.rotateSecret();
        assertEq(tga.secretVersion(), 2);

        tga.rotateSecret();
        assertEq(tga.secretVersion(), 3);
    }

    function test_RotateSecret_OnlyOwner() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.rotateSecret();
    }

    // --- Onboarding ---

    function test_Onboard() public {
        // Register member 1
        bytes32 m1 = _registerDstack();

        // Add second KMS root and register member 2
        tga.addTrustedKmsRoot(kmsRoot2);
        TeeGroupAuth.DstackProof memory proof2 = _buildDstackProof(
            keccak256("handshake2"), kmsPriv2, appPriv, derivedPriv2, DERIVED_PUBKEY2, APP_PUBKEY, appId
        );
        bytes32 m2 = tga.registerDstack(appId, proof2);

        // Onboard m2 from m1 — must be called from m1's derived address
        address derivedAddr = vm.addr(derivedPriv);
        vm.prank(derivedAddr);
        tga.onboard(m1, m2, "encrypted_secret");

        TeeGroupAuth.OnboardMsg[] memory msgs = tga.getOnboarding(m2);
        assertEq(msgs.length, 1);
        assertEq(msgs[0].fromMember, m1);
        assertEq(msgs[0].encryptedPayload, "encrypted_secret");
    }

    function test_Onboard_EmitsEventWithSecretVersion() public {
        bytes32 m1 = _registerDstack();

        tga.addTrustedKmsRoot(kmsRoot2);
        TeeGroupAuth.DstackProof memory proof2 = _buildDstackProof(
            keccak256("handshake2"), kmsPriv2, appPriv, derivedPriv2, DERIVED_PUBKEY2, APP_PUBKEY, appId
        );
        bytes32 m2 = tga.registerDstack(appId, proof2);

        address derivedAddr = vm.addr(derivedPriv);
        vm.expectEmit(true, true, false, true);
        emit TeeGroupAuth.OnboardingPosted(m2, m1, 1);
        vm.prank(derivedAddr);
        tga.onboard(m1, m2, "secret");
    }

    function test_Onboard_RevertFromNotMember() public {
        // Register only m2
        tga.addTrustedKmsRoot(kmsRoot2);
        TeeGroupAuth.DstackProof memory proof2 = _buildDstackProof(
            keccak256("handshake2"), kmsPriv2, appPriv, derivedPriv2, DERIVED_PUBKEY2, APP_PUBKEY, appId
        );
        bytes32 m2 = tga.registerDstack(appId, proof2);
        bytes32 fakeId = keccak256("nobody");

        vm.expectRevert(TeeGroupAuth.MemberNotFound.selector);
        tga.onboard(fakeId, m2, "secret");
    }

    function test_Onboard_RevertToNotMember() public {
        bytes32 m1 = _registerDstack();
        bytes32 fakeId = keccak256("nobody");

        address derivedAddr = vm.addr(derivedPriv);
        vm.prank(derivedAddr);
        vm.expectRevert(TeeGroupAuth.MemberNotFound.selector);
        tga.onboard(m1, fakeId, "secret");
    }

    function test_Onboard_RevertSenderNotFromMember() public {
        bytes32 m1 = _registerDstack();

        tga.addTrustedKmsRoot(kmsRoot2);
        TeeGroupAuth.DstackProof memory proof2 = _buildDstackProof(
            keccak256("handshake2"), kmsPriv2, appPriv, derivedPriv2, DERIVED_PUBKEY2, APP_PUBKEY, appId
        );
        bytes32 m2 = tga.registerDstack(appId, proof2);

        // Try to onboard from a random address (not the derived key owner)
        vm.prank(address(0xBEEF));
        vm.expectRevert(TeeGroupAuth.SenderNotFromMember.selector);
        tga.onboard(m1, m2, "secret");
    }

    // --- Upgrade Path ---

    function test_Upgrade_DeployV1_UpgradeV2_StatePersists() public {
        // Register a member on v1
        bytes32 memberId = _registerDstack();
        assertTrue(tga.isMember(memberId));

        // Rotate secret to version 2
        tga.rotateSecret();
        assertEq(tga.secretVersion(), 2);

        // Deploy V2 implementation
        TeeGroupAuthV2 implV2 = new TeeGroupAuthV2();

        // Upgrade
        tga.upgradeToAndCall(address(implV2), "");

        // Cast to V2 to access new function
        TeeGroupAuthV2 tgaV2 = TeeGroupAuthV2(address(proxy));

        // Verify new function works
        assertEq(tgaV2.version(), 2);

        // Verify state persists
        assertTrue(tgaV2.isMember(memberId));
        assertEq(tgaV2.secretVersion(), 2);
        assertEq(tgaV2.owner(), owner);
        assertTrue(tgaV2.trustedKmsRoots(kmsRoot));
        assertTrue(tgaV2.allowedCode(appId));
    }

    function test_Upgrade_OnlyOwner() public {
        TeeGroupAuthV2 implV2 = new TeeGroupAuthV2();

        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.upgradeToAndCall(address(implV2), "");
    }

    // --- Views ---

    function test_GetMember_NonExistent() public view {
        (bytes32 codeId, bytes memory pubkey, uint256 registeredAt) = tga.getMember(keccak256("nobody"));
        assertEq(codeId, bytes32(0));
        assertEq(pubkey.length, 0);
        assertEq(registeredAt, 0);
    }

    function test_IsMember_False() public view {
        assertFalse(tga.isMember(keccak256("nobody")));
    }

    function test_GetOnboarding_Empty() public view {
        TeeGroupAuth.OnboardMsg[] memory msgs = tga.getOnboarding(keccak256("nobody"));
        assertEq(msgs.length, 0);
    }

    // --- Access Control Comprehensive ---

    function test_OnlyOwnerCanRevokeMembers() public {
        bytes32 memberId = _registerDstack();
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.revokeMember(memberId);
    }

    function test_OnlyOwnerCanRotateSecret() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.rotateSecret();
    }

    function test_OnlyOwnerCanRemoveCode() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(0xBEEF)));
        tga.removeAllowedCode(appId);
    }
}

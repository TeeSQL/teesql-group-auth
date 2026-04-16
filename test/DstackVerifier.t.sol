// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {DstackVerifier} from "../src/DstackVerifier.sol";

/// @dev Tests for DstackVerifier's governance + admin surface, and the
///      structural properties of verify() (decoding, revert paths).
///
///      End-to-end signature-chain validation is done as an integration
///      test against a live Phala CVM via `teesql kms recover-root +
///      registerDstack`, not here. Reproducing a valid dstack 3-level
///      ECDSA chain in a Solidity unit test is fragile compared to
///      exercising it once against real KMS-derived keys.
contract DstackVerifierTest is Test {
    DstackVerifier verifier;
    address owner = address(0xA11CE);
    address kmsRootA = address(0xAAAA);
    address kmsRootB = address(0xBBBB);

    function setUp() public {
        DstackVerifier impl = new DstackVerifier();
        address[] memory roots = new address[](1);
        roots[0] = kmsRootA;
        bytes memory initData = abi.encodeCall(DstackVerifier.initialize, (owner, roots));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        verifier = DstackVerifier(address(proxy));
    }

    function test_initializeSetsOwnerAndSeedRoot() public view {
        assertEq(verifier.owner(), owner);
        assertTrue(verifier.allowedKmsRoots(kmsRootA));
        assertFalse(verifier.allowedKmsRoots(kmsRootB));
    }

    function test_initializeRejectsZeroOwner() public {
        DstackVerifier impl = new DstackVerifier();
        address[] memory roots = new address[](0);
        bytes memory init = abi.encodeCall(DstackVerifier.initialize, (address(0), roots));
        vm.expectRevert(DstackVerifier.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), init);
    }

    function test_initializeRejectsZeroRoot() public {
        DstackVerifier impl = new DstackVerifier();
        address[] memory roots = new address[](1);
        roots[0] = address(0);
        bytes memory init = abi.encodeCall(DstackVerifier.initialize, (owner, roots));
        vm.expectRevert(DstackVerifier.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), init);
    }

    function test_cannotInitializeTwice() public {
        address[] memory roots = new address[](0);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        verifier.initialize(owner, roots);
    }

    function test_ownerCanAddAndRemoveKmsRoot() public {
        vm.prank(owner);
        verifier.addKmsRoot(kmsRootB);
        assertTrue(verifier.allowedKmsRoots(kmsRootB));

        vm.prank(owner);
        verifier.removeKmsRoot(kmsRootB);
        assertFalse(verifier.allowedKmsRoots(kmsRootB));
    }

    function test_addKmsRootRejectsZero() public {
        vm.prank(owner);
        vm.expectRevert(DstackVerifier.ZeroAddress.selector);
        verifier.addKmsRoot(address(0));
    }

    function test_nonOwnerCannotAddKmsRoot() public {
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        verifier.addKmsRoot(kmsRootB);
    }

    function test_verifyRevertsOnMalformedProof() public {
        // A zero-byte proof can't decode into (bytes32, DstackProof) — should revert.
        vm.expectRevert();
        verifier.verify("");
    }

    function test_nonOwnerCannotUpgrade() public {
        DstackVerifier v2 = new DstackVerifier();
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(this)));
        verifier.upgradeToAndCall(address(v2), "");
    }

    function test_ownerCanUpgrade() public {
        DstackVerifier v2 = new DstackVerifier();
        vm.prank(owner);
        verifier.upgradeToAndCall(address(v2), "");
        assertEq(verifier.owner(), owner);
    }
}

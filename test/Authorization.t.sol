// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {TEEBridge} from "../src/TEEBridge.sol";

/// @title Authorization Tests
/// @notice Tests for database access authorization functionality in TEEBridge
contract AuthorizationTest is Test {
    TEEBridge bridge;
    address owner;
    address alice;
    address bob;
    address unauthorized;

    bytes32 constant CLUSTER_XYN = keccak256("xyn");
    bytes32 constant CLUSTER_TEST = keccak256("test");

    uint8 constant PERMISSION_READ = 1;
    uint8 constant PERMISSION_WRITE = 2;
    uint8 constant PERMISSION_READ_WRITE = 3;

    function setUp() public {
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        unauthorized = makeAddr("unauthorized");

        // Deploy implementation
        TEEBridge impl = new TEEBridge();

        // Deploy proxy
        bytes memory initData = abi.encodeCall(
            TEEBridge.initialize,
            (
                owner,
                new address[](0), // no verifiers
                new bytes32[](0)  // no allowed codes
            )
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        bridge = TEEBridge(address(proxy));
    }

    // --- Authorization Management Tests ---

    function test_addAuthorizedSigner_read() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);

        (uint8 permissions, bool active, uint256 authorizedAt) = bridge.getAuthorization(CLUSTER_XYN, alice);
        assertEq(permissions, PERMISSION_READ);
        assertTrue(active);
        assertGt(authorizedAt, 0);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE));
    }

    function test_addAuthorizedSigner_write() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE));
    }

    function test_addAuthorizedSigner_readWrite() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE));
    }

    function test_addAuthorizedSigner_multipleSigners() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);

        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, bob, PERMISSION_READ_WRITE);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, bob, PERMISSION_READ));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, bob, PERMISSION_WRITE));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, bob, PERMISSION_READ_WRITE));
    }

    function test_addAuthorizedSigner_multipleClusters() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);

        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_TEST, alice, PERMISSION_READ_WRITE);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_TEST, alice, PERMISSION_READ));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_TEST, alice, PERMISSION_WRITE));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_TEST, alice, PERMISSION_READ_WRITE));
    }

    function test_revokeAuthorizedSigner() public {
        // First authorize
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));

        // Then revoke
        vm.prank(owner);
        bridge.revokeAuthorizedSigner(CLUSTER_XYN, alice);

        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE));

        // Check that authorization data shows inactive
        (uint8 permissions, bool active, uint256 authorizedAt) = bridge.getAuthorization(CLUSTER_XYN, alice);
        assertEq(permissions, PERMISSION_READ_WRITE); // Permissions still stored
        assertFalse(active); // But marked as inactive
        assertGt(authorizedAt, 0); // Original timestamp preserved
    }

    function test_unauthorizedSigner() public {
        // No authorization granted
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, unauthorized, PERMISSION_READ));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, unauthorized, PERMISSION_WRITE));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, unauthorized, PERMISSION_READ_WRITE));

        (uint8 permissions, bool active, uint256 authorizedAt) = bridge.getAuthorization(CLUSTER_XYN, unauthorized);
        assertEq(permissions, 0);
        assertFalse(active);
        assertEq(authorizedAt, 0);
    }

    // --- Permission Logic Tests ---

    function test_permissionBitfield() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE);

        // Read+write should satisfy all permission checks
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));      // 3 & 1 = 1
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));     // 3 & 2 = 2
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE)); // 3 & 3 = 3
    }

    function test_readOnlyPermissions() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));      // 1 & 1 = 1 ✓
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));     // 1 & 2 = 0 ✗
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE)); // 1 & 3 = 1 ≠ 3 ✗
    }

    function test_writeOnlyPermissions() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE);

        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));      // 2 & 1 = 0 ✗
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));     // 2 & 2 = 2 ✓
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE)); // 2 & 3 = 2 ≠ 3 ✗
    }

    // --- Access Control Tests ---

    function test_onlyOwnerCanAddSigner() public {
        vm.expectRevert();
        vm.prank(alice);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);
    }

    function test_onlyOwnerCanRevokeSigner() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);

        vm.expectRevert();
        vm.prank(alice);
        bridge.revokeAuthorizedSigner(CLUSTER_XYN, alice);
    }

    // --- Input Validation Tests ---

    function test_addSigner_rejectsZeroAddress() public {
        vm.expectRevert();
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, address(0), PERMISSION_READ);
    }

    function test_addSigner_rejectsInvalidPermissions() public {
        vm.expectRevert();
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, 0);

        vm.expectRevert();
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, 4);

        vm.expectRevert();
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, 255);
    }

    // --- Event Tests ---

    function test_addSigner_emitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit SignerAuthorized(CLUSTER_XYN, alice, PERMISSION_READ);

        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);
    }

    function test_revokeSigner_emitsEvent() public {
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);

        vm.expectEmit(true, true, false, true);
        emit SignerRevoked(CLUSTER_XYN, alice);

        vm.prank(owner);
        bridge.revokeAuthorizedSigner(CLUSTER_XYN, alice);
    }

    // --- Integration Tests ---

    function test_authorization_fullWorkflow() public {
        // 1. Authorize Alice with read access
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));

        // 2. Upgrade Alice to read-write access
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE);

        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ_WRITE));

        // 3. Revoke access
        vm.prank(owner);
        bridge.revokeAuthorizedSigner(CLUSTER_XYN, alice);

        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));

        // 4. Re-authorize with different permissions
        vm.prank(owner);
        bridge.addAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE);

        assertFalse(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_READ));
        assertTrue(bridge.isAuthorizedSigner(CLUSTER_XYN, alice, PERMISSION_WRITE));
    }

    // Events for testing
    event SignerAuthorized(bytes32 indexed clusterId, address indexed signer, uint8 permissions);
    event SignerRevoked(bytes32 indexed clusterId, address indexed signer);
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondSmokeTest} from "../DiamondSmoke.t.sol";

import {IBootGate} from "src/interfaces/IBootGate.sol";
import {IAdmin} from "src/interfaces/IAdmin.sol";
import {ICore} from "src/interfaces/ICore.sol";
import {IDstackKmsAdapter} from "src/interfaces/IDstackKmsAdapter.sol";

/// @title BootGateFacetTest
/// @notice Coverage for `BootGateFacet.clusterBootPolicy` - every reject
///         branch (destroyed -> paused -> unknown passthrough -> bad
///         compose -> bad device) plus the all-pass and
///         `allowAnyDevice=true` happy paths. Inherits `DiamondSmokeTest`
///         for the deployed-diamond fixture; each test invokes
///         `_buildDiamond` to get a fresh diamond it can poke at.
contract BootGateFacetTest is DiamondSmokeTest {
    bytes32 internal constant TEST_COMPOSE = 0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 internal constant TEST_DEVICE = 0x3333333333333333333333333333333333333333333333333333333333333333;

    /// @dev Builds the diamond, mints a passthrough so we have a real
    ///      `isOurPassthrough` entry to feed the gate, and seeds the
    ///      compose-hash + device allowlists so the all-pass call returns
    ///      `(true, "")`. Tests that need a specific failure flip the
    ///      relevant axis off.
    function _baseline() internal returns (address passthrough) {
        _buildDiamond();
        IDstackKmsAdapter(address(diamond)).dstack_kms_setKms(address(mockKms));

        passthrough = ICore(address(diamond)).createMember(bytes32(uint256(1)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID);

        IAdmin(address(diamond)).addComposeHash(TEST_COMPOSE);
        IAdmin(address(diamond)).addDevice(TEST_DEVICE);
    }

    function test_clusterBootPolicy_happyPath_returnsTrueEmpty() public {
        address passthrough = _baseline();

        (bool ok, string memory reason) =
            IBootGate(address(diamond)).clusterBootPolicy(passthrough, TEST_COMPOSE, TEST_DEVICE);

        assertTrue(ok, "should pass");
        assertEq(bytes(reason).length, 0, "empty reason on pass");
    }

    function test_clusterBootPolicy_returnsClusterDestroyedFirst() public {
        address passthrough = _baseline();

        // Destroy first - this is irreversible. Any subsequent call must
        // return ("cluster destroyed") regardless of OTHER state.
        IAdmin(address(diamond)).destroy();

        // Pass a deliberately-bad compose hash and an unknown device to
        // verify the destroyed check fires FIRST (highest precedence).
        (bool ok, string memory reason) = IBootGate(address(diamond))
            .clusterBootPolicy(passthrough, bytes32(uint256(0xDEAD)), bytes32(uint256(0xBEEF)));

        assertFalse(ok, "destroy must reject");
        assertEq(reason, "cluster destroyed", "destroy reason");
    }

    function test_clusterBootPolicy_returnsClusterPaused() public {
        address passthrough = _baseline();

        // The smoke-test setUp puts the deployer as pauser; we are the
        // deployer so this call lands.
        IAdmin(address(diamond)).pause();

        // Pass a deliberately-bad compose hash to verify the paused check
        // fires before the compose-hash check.
        (bool ok, string memory reason) =
            IBootGate(address(diamond)).clusterBootPolicy(passthrough, bytes32(uint256(0xDEAD)), TEST_DEVICE);

        assertFalse(ok, "pause must reject");
        assertEq(reason, "cluster paused", "pause reason");
    }

    function test_clusterBootPolicy_returnsUnknownPassthrough() public {
        _baseline();

        // A random address that was never minted via createMember.
        address strangerPassthrough = address(0xFFEE);
        (bool ok, string memory reason) =
            IBootGate(address(diamond)).clusterBootPolicy(strangerPassthrough, TEST_COMPOSE, TEST_DEVICE);

        assertFalse(ok, "unknown passthrough must reject");
        assertEq(reason, "unknown passthrough", "unknown passthrough reason");
    }

    function test_clusterBootPolicy_returnsComposeHashNotAllowed() public {
        address passthrough = _baseline();

        bytes32 unknownHash = bytes32(uint256(0xDEAD));
        (bool ok, string memory reason) =
            IBootGate(address(diamond)).clusterBootPolicy(passthrough, unknownHash, TEST_DEVICE);

        assertFalse(ok, "unallowed compose must reject");
        assertEq(reason, "compose hash not allowed", "compose reason");
    }

    function test_clusterBootPolicy_returnsDeviceNotAllowed() public {
        address passthrough = _baseline();

        // allowAnyDevice is false by default and an unknown device is not
        // in the allowlist => rejection.
        bytes32 unknownDevice = bytes32(uint256(0xC0FFEE));
        (bool ok, string memory reason) =
            IBootGate(address(diamond)).clusterBootPolicy(passthrough, TEST_COMPOSE, unknownDevice);

        assertFalse(ok, "unallowed device must reject");
        assertEq(reason, "device not allowed", "device reason");
    }

    function test_clusterBootPolicy_passesIfAllowAnyDeviceTrue() public {
        address passthrough = _baseline();

        IAdmin(address(diamond)).setAllowAnyDevice(true);

        // An unknown device must now bypass the allowlist check.
        bytes32 unknownDevice = bytes32(uint256(0xC0FFEE));
        (bool ok, string memory reason) =
            IBootGate(address(diamond)).clusterBootPolicy(passthrough, TEST_COMPOSE, unknownDevice);

        assertTrue(ok, "allowAnyDevice should pass any device");
        assertEq(bytes(reason).length, 0, "empty reason on pass");
    }
}

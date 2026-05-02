// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondSmokeTest} from "../DiamondSmoke.t.sol";

import {IAdapterRegistry} from "src/interfaces/IAdapterRegistry.sol";
import {IAdmin} from "src/interfaces/IAdmin.sol";

/// @title AdapterRegistryFacetTest
/// @notice Coverage for `AdapterRegistryFacet`'s read surface - every
///         getter touched at least once, plus the enumeration arrays
///         exercised after registering additional adapters via
///         `IAdmin.registerAttestationAdapter` /
///         `registerKmsAdapter`. Inherits `DiamondSmokeTest` for the
///         deployed diamond + dstack adapter init seed (1 attestation,
///         1 KMS).
contract AdapterRegistryFacetTest is DiamondSmokeTest {
    bytes32 internal constant EXTRA_ATTEST_A =
        0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1;
    bytes32 internal constant EXTRA_ATTEST_B =
        0xa2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2;
    bytes32 internal constant EXTRA_KMS_A =
        0xb1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1;
    bytes32 internal constant EXTRA_KMS_B =
        0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2;

    address internal extraFacetA = address(0xFA1);
    address internal extraFacetB = address(0xFA2);

    function test_attestationFor_returnsZeroForUnknownPassthrough() public {
        _buildDiamond();
        IAdapterRegistry reg = IAdapterRegistry(address(diamond));
        assertEq(reg.attestationFor(address(0xDEAD)), bytes32(0), "zero for unknown");
    }

    function test_kmsFor_returnsZeroForUnknownPassthrough() public {
        _buildDiamond();
        IAdapterRegistry reg = IAdapterRegistry(address(diamond));
        assertEq(reg.kmsFor(address(0xDEAD)), bytes32(0), "zero for unknown");
    }

    function test_listAttestationIds_returnsAllRegistered() public {
        _buildDiamond();
        IAdapterRegistry reg = IAdapterRegistry(address(diamond));

        // Init seeded one attestation id.
        bytes32[] memory pre = reg.listAttestationIds();
        assertEq(pre.length, 1, "init pre-seeds one attestation id");
        assertEq(pre[0], DSTACK_ATTESTATION_ID, "seed 0 is dstack");

        // Register two more.
        IAdmin(address(diamond)).registerAttestationAdapter(EXTRA_ATTEST_A, extraFacetA);
        IAdmin(address(diamond)).registerAttestationAdapter(EXTRA_ATTEST_B, extraFacetB);

        bytes32[] memory post = reg.listAttestationIds();
        assertEq(post.length, 3, "len after 2 registers");
        assertEq(post[0], DSTACK_ATTESTATION_ID, "post[0]");
        assertEq(post[1], EXTRA_ATTEST_A, "post[1]");
        assertEq(post[2], EXTRA_ATTEST_B, "post[2]");
    }

    function test_listKmsIds_returnsAllRegistered() public {
        _buildDiamond();
        IAdapterRegistry reg = IAdapterRegistry(address(diamond));

        bytes32[] memory pre = reg.listKmsIds();
        assertEq(pre.length, 1, "init pre-seeds one kms id");
        assertEq(pre[0], DSTACK_KMS_ID, "seed 0 is dstack kms");

        IAdmin(address(diamond)).registerKmsAdapter(EXTRA_KMS_A, extraFacetA);
        IAdmin(address(diamond)).registerKmsAdapter(EXTRA_KMS_B, extraFacetB);

        bytes32[] memory post = reg.listKmsIds();
        assertEq(post.length, 3, "len after 2 registers");
        assertEq(post[0], DSTACK_KMS_ID, "post[0]");
        assertEq(post[1], EXTRA_KMS_A, "post[1]");
        assertEq(post[2], EXTRA_KMS_B, "post[2]");
    }

    function test_attestationRegistered_returnsBoolCorrectly() public {
        _buildDiamond();
        IAdapterRegistry reg = IAdapterRegistry(address(diamond));

        assertTrue(reg.attestationRegistered(DSTACK_ATTESTATION_ID), "seeded one is true");
        assertFalse(reg.attestationRegistered(EXTRA_ATTEST_A), "unregistered is false");

        IAdmin(address(diamond)).registerAttestationAdapter(EXTRA_ATTEST_A, extraFacetA);
        assertTrue(reg.attestationRegistered(EXTRA_ATTEST_A), "registered is true");

        IAdmin(address(diamond)).deregisterAttestationAdapter(EXTRA_ATTEST_A);
        assertFalse(reg.attestationRegistered(EXTRA_ATTEST_A), "deregistered is false");
    }

    function test_kmsRegistered_returnsBoolCorrectly() public {
        _buildDiamond();
        IAdapterRegistry reg = IAdapterRegistry(address(diamond));

        assertTrue(reg.kmsRegistered(DSTACK_KMS_ID), "seeded one is true");
        assertFalse(reg.kmsRegistered(EXTRA_KMS_A), "unregistered is false");

        IAdmin(address(diamond)).registerKmsAdapter(EXTRA_KMS_A, extraFacetA);
        assertTrue(reg.kmsRegistered(EXTRA_KMS_A), "registered is true");

        IAdmin(address(diamond)).deregisterKmsAdapter(EXTRA_KMS_A);
        assertFalse(reg.kmsRegistered(EXTRA_KMS_A), "deregistered is false");
    }

    function test_defaultAttestationId_returnsInitValue() public {
        _buildDiamond();
        assertEq(
            IAdapterRegistry(address(diamond)).defaultAttestationId(),
            DSTACK_ATTESTATION_ID,
            "default attest id from init"
        );
    }

    function test_defaultKmsId_returnsInitValue() public {
        _buildDiamond();
        assertEq(
            IAdapterRegistry(address(diamond)).defaultKmsId(),
            DSTACK_KMS_ID,
            "default kms id from init"
        );
    }

    function test_attestationFacet_returnsRegisteredAddress() public {
        _buildDiamond();
        IAdapterRegistry reg = IAdapterRegistry(address(diamond));

        assertEq(
            reg.attestationFacet(DSTACK_ATTESTATION_ID),
            address(dstackAttestationFacet),
            "init-seeded facet pointer"
        );
        assertEq(
            reg.attestationFacet(EXTRA_ATTEST_A),
            address(0),
            "unregistered is zero"
        );

        IAdmin(address(diamond)).registerAttestationAdapter(EXTRA_ATTEST_A, extraFacetA);
        assertEq(reg.attestationFacet(EXTRA_ATTEST_A), extraFacetA, "after register");
    }

    function test_kmsFacet_returnsRegisteredAddress() public {
        _buildDiamond();
        IAdapterRegistry reg = IAdapterRegistry(address(diamond));

        assertEq(
            reg.kmsFacet(DSTACK_KMS_ID),
            address(dstackKmsFacet),
            "init-seeded kms facet pointer"
        );
        assertEq(reg.kmsFacet(EXTRA_KMS_A), address(0), "unregistered is zero");

        IAdmin(address(diamond)).registerKmsAdapter(EXTRA_KMS_A, extraFacetA);
        assertEq(reg.kmsFacet(EXTRA_KMS_A), extraFacetA, "after register");
    }
}

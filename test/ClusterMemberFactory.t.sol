// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondSmokeTest} from "../test/DiamondSmoke.t.sol";
import {ClusterMemberFactory} from "src/ClusterMemberFactory.sol";
import {IClusterMemberFactory} from "src/interfaces/IClusterMemberFactory.sol";
import {DstackMember} from "src/members/DstackMember.sol";

/// @title ClusterMemberFactoryTest
/// @notice Coverage for `ClusterMemberFactory`'s previously-untested
///         surfaces - predict view (matches actual deploy + reverts on
///         unregistered runtime), the atomic
///         `deployMemberWithExpectedImpl` drift-detection branch, every
///         revert path on `setMemberImpl` / `deployMember`, and the
///         Ownable2Step admin transfer flow. Inherits `DiamondSmokeTest`
///         only for the chain-singleton setUp (factory + member impl);
///         each test here does its own factory wiring so we do not
///         contaminate the smoke-test fixture.
contract ClusterMemberFactoryTest is DiamondSmokeTest {
    bytes32 internal constant ALT_ATTESTATION_ID =
        0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    address internal stranger = address(0xBEEF);
    address internal newAdmin = address(0xABCD);

    // setMemberImpl ---------------------------------------------------------

    function test_setMemberImpl_firstCallRegistersRuntime() public {
        // Sanity: registry is empty before the first call.
        assertEq(factory.registeredAttestationIds().length, 0, "pre len");

        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));

        bytes32[] memory ids = factory.registeredAttestationIds();
        assertEq(ids.length, 1, "len after first set");
        assertEq(ids[0], DSTACK_ATTESTATION_ID, "id pushed");
        assertEq(
            factory.memberImpl(DSTACK_ATTESTATION_ID),
            address(dstackMemberImpl),
            "impl mapped"
        );
    }

    function test_setMemberImpl_subsequentCallRotatesWithoutAppending() public {
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));

        DstackMember newImpl = new DstackMember();
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(newImpl));

        bytes32[] memory ids = factory.registeredAttestationIds();
        assertEq(ids.length, 1, "no append on rotate");
        assertEq(
            factory.memberImpl(DSTACK_ATTESTATION_ID),
            address(newImpl),
            "impl rotated"
        );
    }

    function test_setMemberImpl_revertsOnZeroId() public {
        vm.expectRevert(IClusterMemberFactory.ZeroAddress.selector);
        factory.setMemberImpl(bytes32(0), address(dstackMemberImpl));
    }

    function test_setMemberImpl_revertsOnZeroImpl() public {
        vm.expectRevert(IClusterMemberFactory.ZeroAddress.selector);
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(0));
    }

    function test_setMemberImpl_revertsOnUnchangedImpl() public {
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
        vm.expectRevert(IClusterMemberFactory.ImplUnchanged.selector);
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
    }

    function test_setMemberImpl_revertsForNonAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(IClusterMemberFactory.NotAdmin.selector);
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
    }

    function test_setMemberImpl_emitsEvent() public {
        vm.expectEmit(true, true, true, true, address(factory));
        emit IClusterMemberFactory.MemberImplUpdated(
            DSTACK_ATTESTATION_ID,
            address(0),
            address(dstackMemberImpl)
        );
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));

        // Also exercise the rotation event (non-zero `oldImpl`).
        DstackMember rotated = new DstackMember();
        vm.expectEmit(true, true, true, true, address(factory));
        emit IClusterMemberFactory.MemberImplUpdated(
            DSTACK_ATTESTATION_ID,
            address(dstackMemberImpl),
            address(rotated)
        );
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(rotated));
    }

    // Deploy + predict + drift ---------------------------------------------

    function test_predict_matchesActualDeployment() public {
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));

        // The "cluster" arg can be any non-zero address - the proxy's
        // `initialize(cluster)` only stores it; this test exercises the
        // predict / deploy address-equality, nothing else.
        address cluster = address(0xC1AE);
        bytes32 salt = bytes32(uint256(7));

        address predicted = factory.predict(cluster, salt, DSTACK_ATTESTATION_ID);
        address actual = factory.deployMember(cluster, salt, DSTACK_ATTESTATION_ID);

        assertEq(predicted, actual, "predict matches deploy");
        assertTrue(actual.code.length > 0, "proxy has bytecode");
    }

    function test_predict_revertsOnUnregisteredRuntime() public {
        vm.expectRevert(IClusterMemberFactory.ImplNotRegistered.selector);
        factory.predict(address(0xC1AE), bytes32(uint256(1)), ALT_ATTESTATION_ID);
    }

    function test_deployMember_revertsOnZeroCluster() public {
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
        vm.expectRevert(IClusterMemberFactory.ZeroAddress.selector);
        factory.deployMember(address(0), bytes32(uint256(1)), DSTACK_ATTESTATION_ID);
    }

    function test_deployMember_revertsOnUnregisteredRuntime() public {
        vm.expectRevert(IClusterMemberFactory.ImplNotRegistered.selector);
        factory.deployMember(address(0xC1AE), bytes32(uint256(1)), ALT_ATTESTATION_ID);
    }

    function test_deployMemberWithExpectedImpl_succeedsWhenImplMatches() public {
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));

        address cluster = address(0xC1AE);
        bytes32 salt = bytes32(uint256(11));

        address predicted = factory.predict(cluster, salt, DSTACK_ATTESTATION_ID);
        address actual = factory.deployMemberWithExpectedImpl(
            cluster, salt, DSTACK_ATTESTATION_ID, address(dstackMemberImpl)
        );

        assertEq(actual, predicted, "atomic deploy address matches predict");
    }

    function test_deployMemberWithExpectedImpl_revertsOnImplDrift() public {
        // Operator predicts against impl A ...
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
        address expectedImpl = address(dstackMemberImpl);

        // ... but the admin sneaks in a rotation to impl B before the deploy.
        DstackMember newImpl = new DstackMember();
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(newImpl));

        vm.expectRevert(IClusterMemberFactory.ImplDriftDetected.selector);
        factory.deployMemberWithExpectedImpl(
            address(0xC1AE),
            bytes32(uint256(1)),
            DSTACK_ATTESTATION_ID,
            expectedImpl
        );
    }

    function test_predictedAddress_changesAfterImplRotation() public {
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
        address cluster = address(0xC1AE);
        bytes32 salt = bytes32(uint256(42));

        address predictedA = factory.predict(cluster, salt, DSTACK_ATTESTATION_ID);

        DstackMember newImpl = new DstackMember();
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(newImpl));

        address predictedB = factory.predict(cluster, salt, DSTACK_ATTESTATION_ID);

        // Different impl bytes go into the CREATE2 init code => different
        // CREATE2 init-code hash => different predicted address. Proves the
        // predict-vs-deploy race surface that `deployMemberWithExpectedImpl`
        // closes.
        assertTrue(predictedA != predictedB, "rotation must change predicted addr");
    }

    // Ownable2Step admin transfer ------------------------------------------

    function test_transferAdmin_setsPendingAdmin_emits() public {
        vm.expectEmit(true, true, true, true, address(factory));
        emit IClusterMemberFactory.AdminTransferStarted(deployer, newAdmin);
        factory.transferAdmin(newAdmin);

        assertEq(factory.pendingAdmin(), newAdmin, "pending admin set");
        // Admin doesn't move until `acceptAdmin`.
        assertEq(factory.admin(), deployer, "admin unchanged until accept");
    }

    function test_transferAdmin_revertsOnZero() public {
        vm.expectRevert(IClusterMemberFactory.ZeroAddress.selector);
        factory.transferAdmin(address(0));
    }

    function test_transferAdmin_revertsForNonAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(IClusterMemberFactory.NotAdmin.selector);
        factory.transferAdmin(newAdmin);
    }

    function test_acceptAdmin_succeedsForPendingAdmin() public {
        factory.transferAdmin(newAdmin);

        vm.expectEmit(true, true, true, true, address(factory));
        emit IClusterMemberFactory.AdminTransferred(deployer, newAdmin);
        vm.prank(newAdmin);
        factory.acceptAdmin();

        assertEq(factory.admin(), newAdmin, "admin rotated");
    }

    function test_acceptAdmin_revertsForNonPendingAdmin() public {
        factory.transferAdmin(newAdmin);

        vm.prank(stranger);
        vm.expectRevert(IClusterMemberFactory.NotPendingAdmin.selector);
        factory.acceptAdmin();
    }

    function test_acceptAdmin_clearsPendingAdmin() public {
        factory.transferAdmin(newAdmin);
        vm.prank(newAdmin);
        factory.acceptAdmin();

        assertEq(factory.pendingAdmin(), address(0), "pendingAdmin cleared");

        // The old admin can no longer rotate impls.
        vm.expectRevert(IClusterMemberFactory.NotAdmin.selector);
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));

        // The new admin can.
        vm.prank(newAdmin);
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
        assertEq(
            factory.memberImpl(DSTACK_ATTESTATION_ID),
            address(dstackMemberImpl),
            "new admin can mutate"
        );
    }
}

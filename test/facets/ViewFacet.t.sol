// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondSmokeTest} from "../DiamondSmoke.t.sol";

import {ViewFacet} from "src/facets/ViewFacet.sol";
import {IAdmin} from "src/interfaces/IAdmin.sol";
import {ICore} from "src/interfaces/ICore.sol";
import {IDstackKmsAdapter} from "src/interfaces/IDstackKmsAdapter.sol";

/// @title IClusterViewFull
/// @notice Local interface for the full ViewFacet read surface - the
///         smoke test only exposes a subset; we add the rest here so we
///         can call into the diamond without importing the facet.
interface IClusterViewFull {
    function clusterId() external view returns (string memory);
    function nextMemberSeq() external view returns (uint256);
    function factory() external view returns (address);
    function destroyedAt() external view returns (uint256);
    function destroyed() external view returns (bool);
    function memberRetiredAt(bytes32) external view returns (uint256);
    function allowedComposeHashes(bytes32) external view returns (bool);
    function allowedDeviceIds(bytes32) external view returns (bool);
    function allowAnyDevice() external view returns (bool);
    function authorizedSigners(address)
        external
        view
        returns (uint8 permissions, bool active, uint256 authorizedAt);
    function isSignerAuthorized(address, uint8) external view returns (bool);
}

/// @title ViewFacetTest
/// @notice Coverage for `ViewFacet`'s previously-untouched getters -
///         every accessor exercised at least once, and the
///         `isSignerAuthorized` bitmask is exercised in both the pass
///         and fail directions to lock down the `permissions & required
///         == required` semantics.
contract ViewFacetTest is DiamondSmokeTest {
    bytes32 internal constant LOCAL_HASH =
        0x4444444444444444444444444444444444444444444444444444444444444444;
    bytes32 internal constant LOCAL_DEVICE =
        0x5555555555555555555555555555555555555555555555555555555555555555;

    address internal localSigner = address(0xC0DE);

    function _v() internal view returns (IClusterViewFull) {
        return IClusterViewFull(address(diamond));
    }

    function test_clusterId_returnsInitialValue() public {
        _buildDiamond();
        assertEq(_v().clusterId(), "test-cluster", "clusterId from init");
    }

    function test_destroyedAt_returnsZeroOnLive_thenTimestamp() public {
        _buildDiamond();
        assertEq(_v().destroyedAt(), 0, "destroyedAt zero pre-destroy");

        // Pin the block timestamp so we can assert exact equality.
        vm.warp(1_700_000_000);
        IAdmin(address(diamond)).destroy();
        assertEq(_v().destroyedAt(), 1_700_000_000, "destroyedAt = block.timestamp");
    }

    function test_destroyed_boolMirrorsTimestamp() public {
        _buildDiamond();
        assertFalse(_v().destroyed(), "destroyed false pre-destroy");

        IAdmin(address(diamond)).destroy();
        assertTrue(_v().destroyed(), "destroyed true post-destroy");
    }

    function test_memberRetiredAt_returnsZero_thenTimestampAfterRetire() public {
        _buildDiamond();
        IDstackKmsAdapter(address(diamond)).dstack_kms_setKms(address(mockKms));
        address passthrough = ICore(address(diamond)).createMember(
            bytes32(uint256(1)),
            DSTACK_ATTESTATION_ID,
            DSTACK_KMS_ID
        );

        // The smoke-test `createMember` flow does NOT execute the full
        // `register` path (which is what writes `members[memberId]`),
        // so we forge the minimum state AdminFacet.retireMember needs:
        //   1. A non-zero `members[memberId].instanceId` so the
        //      UnknownMember guard passes.
        //   2. Nothing else - leader id stays zero, retiredAt stays zero.
        // We pin a deterministic memberId and write `instanceId` directly
        // via vm.store. CoreStorage namespace is at the well-known
        // ERC-7201 slot; `members` lives at offset 3 (clusterId,
        // factory, clusterVersion, then the map).
        bytes32 memberId = keccak256(abi.encode(passthrough, "view-test"));
        bytes32 coreSlot = 0x0d2b39176970d8d514a9c53ecdd18f476e2d8dc24d9a92c32af469b1408bb000;
        bytes32 membersSlot = bytes32(uint256(coreSlot) + 3);
        bytes32 memberStructSlot = keccak256(abi.encode(memberId, membersSlot));
        // instanceId is the first field of the Member struct.
        vm.store(address(diamond), memberStructSlot, bytes32(uint256(uint160(passthrough))));

        assertEq(_v().memberRetiredAt(memberId), 0, "retiredAt zero pre-retire");

        vm.warp(1_700_000_500);
        IAdmin(address(diamond)).retireMember(memberId);
        assertEq(_v().memberRetiredAt(memberId), 1_700_000_500, "retiredAt = ts");
    }

    function test_allowedComposeHashes_falseByDefault_trueAfterAdd() public {
        _buildDiamond();
        assertFalse(_v().allowedComposeHashes(LOCAL_HASH), "false by default");
        IAdmin(address(diamond)).addComposeHash(LOCAL_HASH);
        assertTrue(_v().allowedComposeHashes(LOCAL_HASH), "true after add");
    }

    function test_allowedDeviceIds_falseByDefault_trueAfterAdd() public {
        _buildDiamond();
        assertFalse(_v().allowedDeviceIds(LOCAL_DEVICE), "false by default");
        IAdmin(address(diamond)).addDevice(LOCAL_DEVICE);
        assertTrue(_v().allowedDeviceIds(LOCAL_DEVICE), "true after add");
    }

    function test_allowAnyDevice_falseByDefault_trueAfterSet() public {
        _buildDiamond();
        assertFalse(_v().allowAnyDevice(), "false by default");
        IAdmin(address(diamond)).setAllowAnyDevice(true);
        assertTrue(_v().allowAnyDevice(), "true after set");
    }

    function test_authorizedSigners_returnsThreeTupleAfterAuthorize() public {
        _buildDiamond();

        // Pre-authorize: all-zero tuple.
        (uint8 permsPre, bool activePre, uint256 atPre) = _v().authorizedSigners(localSigner);
        assertEq(permsPre, 0, "perms zero pre");
        assertFalse(activePre, "inactive pre");
        assertEq(atPre, 0, "ts zero pre");

        vm.warp(1_700_000_000);
        IAdmin(address(diamond)).authorizeSigner(localSigner, 3);

        (uint8 perms, bool active, uint256 authorizedAt) = _v().authorizedSigners(localSigner);
        assertEq(perms, 3, "perms = 3");
        assertTrue(active, "active");
        assertEq(authorizedAt, 1_700_000_000, "ts pinned");
    }

    function test_isSignerAuthorized_bitmaskCheckPasses_andFails() public {
        _buildDiamond();

        // Authorize with permissions = 0b01 (read-only).
        IAdmin(address(diamond)).authorizeSigner(localSigner, 1);

        // required=1 (read) - the signer's perms (1) bit-and required (1)
        // == 1 -> pass.
        assertTrue(_v().isSignerAuthorized(localSigner, 1), "read required passes");

        // required=2 (write) - perms (0b01) & 0b10 == 0, but required = 2
        // -> fail.
        assertFalse(_v().isSignerAuthorized(localSigner, 2), "write required fails");

        // required=3 (read+write) - perms 0b01 & 0b11 = 0b01 != 0b11 -> fail.
        assertFalse(_v().isSignerAuthorized(localSigner, 3), "rw required fails");

        // Now elevate to 0b11.
        IAdmin(address(diamond)).authorizeSigner(localSigner, 3);
        assertTrue(_v().isSignerAuthorized(localSigner, 1), "read still passes");
        assertTrue(_v().isSignerAuthorized(localSigner, 2), "write now passes");
        assertTrue(_v().isSignerAuthorized(localSigner, 3), "rw now passes");

        // Revoke flips `active=false`; bitmask irrelevant.
        IAdmin(address(diamond)).revokeSigner(localSigner);
        assertFalse(_v().isSignerAuthorized(localSigner, 1), "revoked = no perms");
    }

    function test_nextMemberSeq_incrementsOnDefaultSaltCreateMember() public {
        _buildDiamond();
        IDstackKmsAdapter(address(diamond)).dstack_kms_setKms(address(mockKms));

        // Fresh diamond - no default-salt mints yet.
        assertEq(_v().nextMemberSeq(), 0, "seq starts at 0");

        // First default-salt mint: uses seq=0, post-increments to 1.
        ICore(address(diamond)).createMember(
            bytes32(0),
            DSTACK_ATTESTATION_ID,
            DSTACK_KMS_ID
        );
        assertEq(_v().nextMemberSeq(), 1, "seq goes to 1 after first default-salt mint");

        // Second default-salt mint: uses seq=1, post-increments to 2.
        ICore(address(diamond)).createMember(
            bytes32(0),
            DSTACK_ATTESTATION_ID,
            DSTACK_KMS_ID
        );
        assertEq(_v().nextMemberSeq(), 2, "seq goes to 2 after second default-salt mint");
    }

    function test_factory_returnsInitFactoryAddress() public {
        _buildDiamond();
        assertEq(_v().factory(), address(factory), "factory pointer from init");
    }
}

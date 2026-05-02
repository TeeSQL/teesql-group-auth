// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondSmokeTest, IClusterView, MockDstackKms} from "../DiamondSmoke.t.sol";

import {IDiamondReadable} from "@solidstate/contracts/proxy/diamond/readable/IDiamondReadable.sol";
import {IERC2535DiamondCutInternal} from
    "@solidstate/contracts/interfaces/IERC2535DiamondCutInternal.sol";
import {IERC2535DiamondCut} from "@solidstate/contracts/interfaces/IERC2535DiamondCut.sol";
import {IERC173} from "@solidstate/contracts/interfaces/IERC173.sol";
import {ISafeOwnable} from "@solidstate/contracts/access/ownable/ISafeOwnable.sol";
import {ISafeOwnableInternal} from "@solidstate/contracts/access/ownable/ISafeOwnableInternal.sol";
import {IOwnableInternal} from "@solidstate/contracts/access/ownable/IOwnableInternal.sol";

import {IAdmin} from "src/interfaces/IAdmin.sol";
import {IAdapterRegistry} from "src/interfaces/IAdapterRegistry.sol";
import {ICore} from "src/interfaces/ICore.sol";
import {AdminFacet} from "src/facets/AdminFacet.sol";
import {ViewFacet} from "src/facets/ViewFacet.sol";
import {CoreStorage} from "src/storage/CoreStorage.sol";

/// @notice Mirror of `ViewFacet.isSignerAuthorized` so tests can call into the
///         diamond's signer-bitmask getter without importing the facet contract.
interface IClusterSignerView {
    function isSignerAuthorized(address s, uint8 required) external view returns (bool);
    function authorizedSigners(address s)
        external
        view
        returns (uint8 permissions, bool active, uint256 authorizedAt);
}

/// @notice Comprehensive test suite for `AdminFacet`. Inherits the full diamond
///         bring-up from `DiamondSmokeTest._buildDiamond()` so each test starts
///         from a freshly-cut diamond with the deployer as the cluster +
///         solidstate owner.
contract AdminFacetTest is DiamondSmokeTest {
    // --- Common test fixtures ---------------------------------------------

    address internal constant RANDOM_EOA = address(0xDEADBEEF);
    address internal constant NEW_PAUSER = address(0xCAFE);
    address internal constant NEW_OWNER = address(0xC0FFEE);
    address internal constant SIGNER_A = address(0x5161E1A);

    bytes32 internal constant HASH_A =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 internal constant DEVICE_A =
        0x3333333333333333333333333333333333333333333333333333333333333333;

    // CoreStorage.Layout slot offsets (relative to CoreStorage.SLOT). See
    // CoreStorage.sol -- the struct field order is the source of truth.
    uint256 internal constant CORE_MEMBERS_OFFSET = 3;
    uint256 internal constant CORE_LEADER_MEMBER_ID_OFFSET = 9;
    uint256 internal constant CORE_IS_OUR_PASSTHROUGH_OFFSET = 11;

    bytes32 internal constant FAKE_ATTEST_ID =
        0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    bytes32 internal constant FAKE_KMS_ID =
        0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;
    address internal constant FAKE_FACET = address(0xBADCAFE);

    // --- Helpers -----------------------------------------------------------

    /// @dev Mark `addr` as a registered passthrough by writing
    ///      `isOurPassthrough[addr] = true` directly into CoreStorage. Bypasses
    ///      the full `createMember` factory deploy + KMS register dance, which
    ///      keeps the auth-side tests focused on AdminFacet's gates rather than
    ///      Core's lifecycle.
    function _markPassthrough(address addr) internal {
        bytes32 slot = keccak256(
            abi.encode(
                addr,
                bytes32(uint256(CoreStorage.SLOT) + CORE_IS_OUR_PASSTHROUGH_OFFSET)
            )
        );
        vm.store(address(diamond), slot, bytes32(uint256(1)));
    }

    /// @dev Plant a bare member entry for `memberId` so AdminFacet's
    ///      `retireMember` sees `instanceId != 0`. We only set the first
    ///      struct slot (instanceId) -- the other Member fields are
    ///      irrelevant to AdminFacet's checks. Avoids the registration-proof
    ///      bootstrap that would otherwise be required to mint a real
    ///      member for retire tests.
    function _plantMember(bytes32 memberId, address instanceId) internal {
        bytes32 base = keccak256(
            abi.encode(
                memberId,
                bytes32(uint256(CoreStorage.SLOT) + CORE_MEMBERS_OFFSET)
            )
        );
        vm.store(address(diamond), base, bytes32(uint256(uint160(instanceId))));
    }

    /// @dev Set `leaderMemberId` directly so we can retire-the-leader-fail
    ///      without bootstrapping a full leader-claim flow with witnesses.
    function _setLeader(bytes32 memberId) internal {
        bytes32 slot = bytes32(uint256(CoreStorage.SLOT) + CORE_LEADER_MEMBER_ID_OFFSET);
        vm.store(address(diamond), slot, memberId);
    }

    // --- 1. Allowlist mutators (Cluster.Allowlists writes) -----------------

    function test_addComposeHash_writesAndEmits() public {
        _buildDiamond();
        vm.expectEmit(false, false, false, true, address(diamond));
        emit IAdmin.ComposeHashAdded(HASH_A);
        IAdmin(address(diamond)).addComposeHash(HASH_A);
        assertTrue(IClusterView(address(diamond)).allowedComposeHashes(HASH_A));
    }

    function test_removeComposeHash_clearsAndEmits() public {
        _buildDiamond();
        IAdmin(address(diamond)).addComposeHash(HASH_A);
        assertTrue(IClusterView(address(diamond)).allowedComposeHashes(HASH_A));
        vm.expectEmit(false, false, false, true, address(diamond));
        emit IAdmin.ComposeHashRemoved(HASH_A);
        IAdmin(address(diamond)).removeComposeHash(HASH_A);
        assertFalse(IClusterView(address(diamond)).allowedComposeHashes(HASH_A));
    }

    function test_addDevice_writesAndEmits() public {
        _buildDiamond();
        vm.expectEmit(false, false, false, true, address(diamond));
        emit IAdmin.DeviceAdded(DEVICE_A);
        IAdmin(address(diamond)).addDevice(DEVICE_A);
        assertTrue(IClusterView(address(diamond)).allowedDeviceIds(DEVICE_A));
    }

    function test_removeDevice_clearsAndEmits() public {
        _buildDiamond();
        IAdmin(address(diamond)).addDevice(DEVICE_A);
        assertTrue(IClusterView(address(diamond)).allowedDeviceIds(DEVICE_A));
        vm.expectEmit(false, false, false, true, address(diamond));
        emit IAdmin.DeviceRemoved(DEVICE_A);
        IAdmin(address(diamond)).removeDevice(DEVICE_A);
        assertFalse(IClusterView(address(diamond)).allowedDeviceIds(DEVICE_A));
    }

    function test_setAllowAnyDevice_togglesAndEmits() public {
        _buildDiamond();
        // false (default) -> true
        vm.expectEmit(false, false, false, true, address(diamond));
        emit IAdmin.AllowAnyDeviceSet(true);
        IAdmin(address(diamond)).setAllowAnyDevice(true);
        assertTrue(IClusterView(address(diamond)).allowAnyDevice());

        // true -> false
        vm.expectEmit(false, false, false, true, address(diamond));
        emit IAdmin.AllowAnyDeviceSet(false);
        IAdmin(address(diamond)).setAllowAnyDevice(false);
        assertFalse(IClusterView(address(diamond)).allowAnyDevice());

        // false -> true again
        vm.expectEmit(false, false, false, true, address(diamond));
        emit IAdmin.AllowAnyDeviceSet(true);
        IAdmin(address(diamond)).setAllowAnyDevice(true);
        assertTrue(IClusterView(address(diamond)).allowAnyDevice());
    }

    function test_addComposeHash_revertsForUnauthorizedCaller() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).addComposeHash(HASH_A);
    }

    function test_addComposeHash_succeedsFromRegisteredPassthrough() public {
        _buildDiamond();
        address fakePassthrough = address(0x9001);
        _markPassthrough(fakePassthrough);
        vm.prank(fakePassthrough);
        IAdmin(address(diamond)).addComposeHash(HASH_A);
        assertTrue(IClusterView(address(diamond)).allowedComposeHashes(HASH_A));
    }

    function test_addComposeHash_revertsAfterDestroy() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).addComposeHash(HASH_A);
    }

    function test_removeComposeHash_revertsAfterDestroy() public {
        _buildDiamond();
        IAdmin(address(diamond)).addComposeHash(HASH_A);
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).removeComposeHash(HASH_A);
    }

    function test_addDevice_revertsAfterDestroy() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).addDevice(DEVICE_A);
    }

    function test_setAllowAnyDevice_revertsAfterDestroy() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).setAllowAnyDevice(true);
    }

    // --- 2. Signer authorization -------------------------------------------

    function test_authorizeSigner_writesAllFields() public {
        _buildDiamond();
        vm.warp(1_700_000_000);
        vm.expectEmit(true, false, false, true, address(diamond));
        emit IAdmin.SignerAuthorized(SIGNER_A, 3);
        IAdmin(address(diamond)).authorizeSigner(SIGNER_A, 3);

        (uint8 perms, bool active, uint256 authorizedAt) =
            IClusterSignerView(address(diamond)).authorizedSigners(SIGNER_A);
        assertEq(perms, 3, "perms");
        assertTrue(active, "active");
        assertEq(authorizedAt, 1_700_000_000, "authorizedAt");
    }

    function test_authorizeSigner_revertsOnZeroAddress() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.ZeroAddress.selector);
        IAdmin(address(diamond)).authorizeSigner(address(0), 1);
    }

    function test_authorizeSigner_revertsOnZeroPerms() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.BadPerms.selector);
        IAdmin(address(diamond)).authorizeSigner(SIGNER_A, 0);
    }

    function test_authorizeSigner_revertsOnPermsTooHigh() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.BadPerms.selector);
        IAdmin(address(diamond)).authorizeSigner(SIGNER_A, 4);
    }

    function test_authorizeSigner_revertsForNonOwner() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).authorizeSigner(SIGNER_A, 1);
    }

    function test_revokeSigner_clearsActive() public {
        _buildDiamond();
        IAdmin(address(diamond)).authorizeSigner(SIGNER_A, 3);
        (uint8 permsBefore, bool activeBefore,) =
            IClusterSignerView(address(diamond)).authorizedSigners(SIGNER_A);
        assertEq(permsBefore, 3);
        assertTrue(activeBefore);

        vm.expectEmit(true, false, false, true, address(diamond));
        emit IAdmin.SignerRevoked(SIGNER_A);
        IAdmin(address(diamond)).revokeSigner(SIGNER_A);

        (uint8 permsAfter, bool activeAfter,) =
            IClusterSignerView(address(diamond)).authorizedSigners(SIGNER_A);
        assertEq(permsAfter, 3, "permissions preserved");
        assertFalse(activeAfter, "active flipped");
    }

    function test_isSignerAuthorized_checksBitmask() public {
        _buildDiamond();
        // perms = 0b11 = 3 (read + write, say)
        IAdmin(address(diamond)).authorizeSigner(SIGNER_A, 3);
        IClusterSignerView v = IClusterSignerView(address(diamond));

        assertTrue(v.isSignerAuthorized(SIGNER_A, 1), "subset 0b01 ok");
        assertTrue(v.isSignerAuthorized(SIGNER_A, 2), "subset 0b10 ok");
        assertTrue(v.isSignerAuthorized(SIGNER_A, 3), "exact 0b11 ok");

        // Now reduce perms to 1; bitmask 2 should fail.
        IAdmin(address(diamond)).authorizeSigner(SIGNER_A, 1);
        assertTrue(v.isSignerAuthorized(SIGNER_A, 1), "0b01 ok at perm=1");
        assertFalse(v.isSignerAuthorized(SIGNER_A, 2), "0b10 fails at perm=1");
        assertFalse(v.isSignerAuthorized(SIGNER_A, 3), "0b11 fails at perm=1");

        // After revocation, no permission bits pass even though `permissions` is preserved.
        IAdmin(address(diamond)).revokeSigner(SIGNER_A);
        assertFalse(v.isSignerAuthorized(SIGNER_A, 1), "revoked -> fail");
    }

    // --- 3. Pause flow -----------------------------------------------------

    function test_setPauser_writesAndEmits() public {
        _buildDiamond();
        vm.expectEmit(true, false, false, true, address(diamond));
        emit IAdmin.PauserSet(NEW_PAUSER);
        IAdmin(address(diamond)).setPauser(NEW_PAUSER);
        assertEq(IAdmin(address(diamond)).pauser(), NEW_PAUSER);
    }

    function test_setPauser_revertsOnZero() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.ZeroAddress.selector);
        IAdmin(address(diamond)).setPauser(address(0));
    }

    function test_setPauser_revertsForNonOwner() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).setPauser(NEW_PAUSER);
    }

    function test_setPauser_revertsAfterDestroy() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).setPauser(NEW_PAUSER);
    }

    function test_pause_revertsForNonPauser() public {
        _buildDiamond();
        // Pauser is the deployer (per DiamondInit args). A random EOA is not.
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).pause();
    }

    function test_pause_thenUnpause_clean() public {
        _buildDiamond();
        // Default pauser is deployer (= address(this)).
        assertFalse(IAdmin(address(diamond)).paused(), "fresh: not paused");

        vm.expectEmit(true, false, false, true, address(diamond));
        emit AdminFacet.Paused(deployer);
        IAdmin(address(diamond)).pause();
        assertTrue(IAdmin(address(diamond)).paused(), "after pause");

        vm.expectEmit(true, false, false, true, address(diamond));
        emit AdminFacet.Unpaused(deployer);
        IAdmin(address(diamond)).unpause();
        assertFalse(IAdmin(address(diamond)).paused(), "after unpause");
    }

    function test_unpause_revertsForNonOwner() public {
        _buildDiamond();
        IAdmin(address(diamond)).pause();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).unpause();
    }

    function test_pause_byNonOwnerPauser_succeeds() public {
        _buildDiamond();
        IAdmin(address(diamond)).setPauser(NEW_PAUSER);
        vm.prank(NEW_PAUSER);
        IAdmin(address(diamond)).pause();
        assertTrue(IAdmin(address(diamond)).paused(), "pauser-but-not-owner can pause");
    }

    // --- 4. Lifecycle: destroy ---------------------------------------------

    function test_destroy_writesTimestampAndEmits() public {
        _buildDiamond();
        vm.warp(1_710_000_000);
        vm.expectEmit(false, false, false, true, address(diamond));
        emit AdminFacet.ClusterDestroyed(1_710_000_000);
        IAdmin(address(diamond)).destroy();
        assertEq(IClusterView(address(diamond)).destroyedAt(), 1_710_000_000);
    }

    function test_destroy_revertsForNonOwner() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).destroy();
    }

    function test_destroy_idempotentRevert() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).destroy();
    }

    function test_destroy_blocksAllowlistMutators() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).addComposeHash(HASH_A);
    }

    function test_destroy_blocksSetPauser() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).setPauser(NEW_PAUSER);
    }

    function test_destroy_blocksAuthorizeSigner() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).authorizeSigner(SIGNER_A, 1);
    }

    function test_destroy_blocksRegisterAdapter() public {
        _buildDiamond();
        IAdmin(address(diamond)).destroy();
        vm.expectRevert(AdminFacet.AlreadyDestroyed.selector);
        IAdmin(address(diamond)).registerAttestationAdapter(FAKE_ATTEST_ID, FAKE_FACET);
    }

    /// @notice Per AdminFacet.sol the `unpause` selector has only `onlyOwner` --
    ///         no `whenNotDestroyed` modifier. By design (spec section 10
    ///         forensic readability + the cleanup path described in the test
    ///         header): after destroy the cluster owner can still flip
    ///         `paused` off so read paths stay live for forensic tooling.
    function test_destroy_doesNotBlockUnpause() public {
        _buildDiamond();
        IAdmin(address(diamond)).pause();
        IAdmin(address(diamond)).destroy();
        // No revert -- unpause is intentionally available post-destroy.
        IAdmin(address(diamond)).unpause();
        assertFalse(IAdmin(address(diamond)).paused());
    }

    // --- 5. Lifecycle: retireMember ----------------------------------------

    function test_retireMember_happyPath() public {
        _buildDiamond();
        bytes32 memberId = keccak256("member-1");
        _plantMember(memberId, address(0x1111));

        vm.warp(1_715_000_000);
        vm.expectEmit(true, false, false, true, address(diamond));
        emit AdminFacet.MemberRetired(memberId, 1_715_000_000);
        IAdmin(address(diamond)).retireMember(memberId);

        assertEq(IClusterView(address(diamond)).memberRetiredAt(memberId), 1_715_000_000);
    }

    function test_retireMember_revertsOnNonExistentMember() public {
        _buildDiamond();
        bytes32 ghostId = keccak256("ghost");
        vm.expectRevert(AdminFacet.UnknownMember.selector);
        IAdmin(address(diamond)).retireMember(ghostId);
    }

    function test_retireMember_revertsOnAlreadyRetired() public {
        _buildDiamond();
        bytes32 memberId = keccak256("member-2");
        _plantMember(memberId, address(0x2222));
        IAdmin(address(diamond)).retireMember(memberId);

        vm.expectRevert(AdminFacet.AlreadyRetired.selector);
        IAdmin(address(diamond)).retireMember(memberId);
    }

    function test_retireMember_revertsOnLeader() public {
        _buildDiamond();
        bytes32 leaderId = keccak256("leader-member");
        _plantMember(leaderId, address(0x3333));
        _setLeader(leaderId);

        vm.expectRevert(AdminFacet.CannotRetireLeader.selector);
        IAdmin(address(diamond)).retireMember(leaderId);
    }

    function test_retireMember_revertsForNonOwner() public {
        _buildDiamond();
        bytes32 memberId = keccak256("member-3");
        _plantMember(memberId, address(0x4444));
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).retireMember(memberId);
    }

    // --- 6. Adapter management -- attestation axis ------------------------

    function test_registerAttestationAdapter_addsToEnumeration() public {
        _buildDiamond();

        // The DSTACK_ATTESTATION_ID was seeded by DiamondInit; one more id
        // should be appended.
        bytes32[] memory before = IAdapterRegistry(address(diamond)).listAttestationIds();
        assertEq(before.length, 1, "DiamondInit pre-seeds one id");

        bytes32 idA = keccak256("att-A");
        vm.expectEmit(true, true, false, true, address(diamond));
        emit IAdmin.AttestationAdapterRegistered(idA, FAKE_FACET);
        IAdmin(address(diamond)).registerAttestationAdapter(idA, FAKE_FACET);

        bytes32[] memory afterA = IAdapterRegistry(address(diamond)).listAttestationIds();
        assertEq(afterA.length, 2, "first new id appended");
        assertEq(afterA[1], idA, "appended in order");
        assertEq(IAdapterRegistry(address(diamond)).attestationFacet(idA), FAKE_FACET);
        assertTrue(IAdapterRegistry(address(diamond)).attestationRegistered(idA));

        // Re-registering the SAME id (e.g., to rotate the facet pointer)
        // must NOT push a duplicate into the enumeration array.
        address newFacet = address(0xBAD2);
        IAdmin(address(diamond)).registerAttestationAdapter(idA, newFacet);
        bytes32[] memory afterReregister =
            IAdapterRegistry(address(diamond)).listAttestationIds();
        assertEq(afterReregister.length, 2, "re-register doesn't duplicate enumeration");
        assertEq(IAdapterRegistry(address(diamond)).attestationFacet(idA), newFacet);

        // A SECOND distinct id appends.
        bytes32 idB = keccak256("att-B");
        IAdmin(address(diamond)).registerAttestationAdapter(idB, FAKE_FACET);
        bytes32[] memory afterB = IAdapterRegistry(address(diamond)).listAttestationIds();
        assertEq(afterB.length, 3);
        assertEq(afterB[2], idB);
    }

    function test_registerAttestationAdapter_revertsOnZeroId() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.ZeroAddress.selector);
        IAdmin(address(diamond)).registerAttestationAdapter(bytes32(0), FAKE_FACET);
    }

    function test_registerAttestationAdapter_revertsOnZeroFacet() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.ZeroAddress.selector);
        IAdmin(address(diamond)).registerAttestationAdapter(FAKE_ATTEST_ID, address(0));
    }

    function test_registerAttestationAdapter_revertsForNonOwner() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).registerAttestationAdapter(FAKE_ATTEST_ID, FAKE_FACET);
    }

    function test_deregisterAttestationAdapter_flipsRegisteredFalse() public {
        _buildDiamond();
        // Pre-seeded by DiamondInit.
        assertTrue(IAdapterRegistry(address(diamond)).attestationRegistered(DSTACK_ATTESTATION_ID));

        vm.expectEmit(true, false, false, true, address(diamond));
        emit IAdmin.AttestationAdapterDeregistered(DSTACK_ATTESTATION_ID);
        IAdmin(address(diamond)).deregisterAttestationAdapter(DSTACK_ATTESTATION_ID);

        assertFalse(
            IAdapterRegistry(address(diamond)).attestationRegistered(DSTACK_ATTESTATION_ID),
            "registered flipped"
        );
        // Facet pointer survives -- soft-disable, not erase.
        assertEq(
            IAdapterRegistry(address(diamond)).attestationFacet(DSTACK_ATTESTATION_ID),
            address(dstackAttestationFacet),
            "facet pointer survives"
        );
    }

    function test_deregisterAttestationAdapter_revertsOnUnknown() public {
        _buildDiamond();
        bytes32 unknown = keccak256("unknown");
        vm.expectRevert(IAdmin.NotRegistered.selector);
        IAdmin(address(diamond)).deregisterAttestationAdapter(unknown);
    }

    function test_deregisterAttestationAdapter_revertsForNonOwner() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).deregisterAttestationAdapter(DSTACK_ATTESTATION_ID);
    }

    function test_deregisterAttestationAdapter_blocksFutureCreateMember() public {
        _buildDiamond();
        IAdmin(address(diamond)).deregisterAttestationAdapter(DSTACK_ATTESTATION_ID);
        vm.expectRevert(ICore.AdapterNotRegistered.selector);
        ICore(address(diamond)).createMember(
            bytes32(uint256(99)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );
    }

    function test_deregisterAttestationAdapter_canBeReRegistered() public {
        _buildDiamond();
        IAdmin(address(diamond)).deregisterAttestationAdapter(DSTACK_ATTESTATION_ID);
        assertFalse(
            IAdapterRegistry(address(diamond)).attestationRegistered(DSTACK_ATTESTATION_ID)
        );
        // Flip back: re-register with the same facet pointer.
        IAdmin(address(diamond)).registerAttestationAdapter(
            DSTACK_ATTESTATION_ID, address(dstackAttestationFacet)
        );
        assertTrue(
            IAdapterRegistry(address(diamond)).attestationRegistered(DSTACK_ATTESTATION_ID),
            "re-registered"
        );
    }

    function test_setDefaultAttestationAdapter_revertsOnUnregistered() public {
        _buildDiamond();
        bytes32 unknown = keccak256("never-seen");
        vm.expectRevert(IAdmin.NotRegistered.selector);
        IAdmin(address(diamond)).setDefaultAttestationAdapter(unknown);
    }

    function test_setDefaultAttestationAdapter_succeedsForRegistered() public {
        _buildDiamond();
        bytes32 idA = keccak256("att-A");
        IAdmin(address(diamond)).registerAttestationAdapter(idA, FAKE_FACET);

        vm.expectEmit(true, false, false, true, address(diamond));
        emit IAdmin.DefaultAttestationSet(idA);
        IAdmin(address(diamond)).setDefaultAttestationAdapter(idA);

        assertEq(IAdapterRegistry(address(diamond)).defaultAttestationId(), idA);
    }

    // --- 7. Adapter management -- KMS axis (symmetric) ---------------------

    function test_registerKmsAdapter_addsToEnumeration() public {
        _buildDiamond();
        bytes32[] memory before = IAdapterRegistry(address(diamond)).listKmsIds();
        assertEq(before.length, 1, "DiamondInit pre-seeds one kms id");

        bytes32 idA = keccak256("kms-A");
        vm.expectEmit(true, true, false, true, address(diamond));
        emit IAdmin.KmsAdapterRegistered(idA, FAKE_FACET);
        IAdmin(address(diamond)).registerKmsAdapter(idA, FAKE_FACET);

        bytes32[] memory afterA = IAdapterRegistry(address(diamond)).listKmsIds();
        assertEq(afterA.length, 2);
        assertEq(afterA[1], idA);
        assertEq(IAdapterRegistry(address(diamond)).kmsFacet(idA), FAKE_FACET);
        assertTrue(IAdapterRegistry(address(diamond)).kmsRegistered(idA));
    }

    function test_registerKmsAdapter_revertsOnZeroId() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.ZeroAddress.selector);
        IAdmin(address(diamond)).registerKmsAdapter(bytes32(0), FAKE_FACET);
    }

    function test_registerKmsAdapter_revertsOnZeroFacet() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.ZeroAddress.selector);
        IAdmin(address(diamond)).registerKmsAdapter(FAKE_KMS_ID, address(0));
    }

    function test_registerKmsAdapter_revertsForNonOwner() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).registerKmsAdapter(FAKE_KMS_ID, FAKE_FACET);
    }

    function test_deregisterKmsAdapter_flipsRegisteredFalse() public {
        _buildDiamond();
        assertTrue(IAdapterRegistry(address(diamond)).kmsRegistered(DSTACK_KMS_ID));
        vm.expectEmit(true, false, false, true, address(diamond));
        emit IAdmin.KmsAdapterDeregistered(DSTACK_KMS_ID);
        IAdmin(address(diamond)).deregisterKmsAdapter(DSTACK_KMS_ID);
        assertFalse(IAdapterRegistry(address(diamond)).kmsRegistered(DSTACK_KMS_ID));
        assertEq(
            IAdapterRegistry(address(diamond)).kmsFacet(DSTACK_KMS_ID),
            address(dstackKmsFacet),
            "facet pointer survives"
        );
    }

    function test_deregisterKmsAdapter_revertsOnUnknown() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.NotRegistered.selector);
        IAdmin(address(diamond)).deregisterKmsAdapter(keccak256("unknown-kms"));
    }

    function test_deregisterKmsAdapter_revertsForNonOwner() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).deregisterKmsAdapter(DSTACK_KMS_ID);
    }

    function test_deregisterKmsAdapter_blocksFutureCreateMember() public {
        _buildDiamond();
        IAdmin(address(diamond)).deregisterKmsAdapter(DSTACK_KMS_ID);
        vm.expectRevert(ICore.AdapterNotRegistered.selector);
        ICore(address(diamond)).createMember(
            bytes32(uint256(123)), DSTACK_ATTESTATION_ID, DSTACK_KMS_ID
        );
    }

    function test_deregisterKmsAdapter_canBeReRegistered() public {
        _buildDiamond();
        IAdmin(address(diamond)).deregisterKmsAdapter(DSTACK_KMS_ID);
        assertFalse(IAdapterRegistry(address(diamond)).kmsRegistered(DSTACK_KMS_ID));
        IAdmin(address(diamond)).registerKmsAdapter(DSTACK_KMS_ID, address(dstackKmsFacet));
        assertTrue(IAdapterRegistry(address(diamond)).kmsRegistered(DSTACK_KMS_ID));
    }

    function test_setDefaultKmsAdapter_revertsOnUnregistered() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.NotRegistered.selector);
        IAdmin(address(diamond)).setDefaultKmsAdapter(keccak256("nope"));
    }

    function test_setDefaultKmsAdapter_succeedsForRegistered() public {
        _buildDiamond();
        bytes32 idA = keccak256("kms-A");
        IAdmin(address(diamond)).registerKmsAdapter(idA, FAKE_FACET);

        vm.expectEmit(true, false, false, true, address(diamond));
        emit IAdmin.DefaultKmsSet(idA);
        IAdmin(address(diamond)).setDefaultKmsAdapter(idA);

        assertEq(IAdapterRegistry(address(diamond)).defaultKmsId(), idA);
    }

    // --- 8. Solidstate ownership transfer flow -----------------------------

    function test_owner_returnsSolidstateOwner() public {
        _buildDiamond();
        // DiamondInit overwrote OwnableStorage.owner from the deployer (CVM
        // ctor caller -- i.e., this contract) to args.owner (= deployer);
        // they happen to be the same, so the surface returns the deployer.
        assertEq(IERC173(address(diamond)).owner(), deployer);
    }

    function test_transferOwnership_setsNominee() public {
        _buildDiamond();
        IERC173(address(diamond)).transferOwnership(NEW_OWNER);
        assertEq(
            ISafeOwnable(address(diamond)).nomineeOwner(),
            NEW_OWNER,
            "nominee written"
        );
        assertEq(IERC173(address(diamond)).owner(), deployer, "owner unchanged");
    }

    function test_acceptOwnership_completesTransfer() public {
        _buildDiamond();
        IERC173(address(diamond)).transferOwnership(NEW_OWNER);
        vm.prank(NEW_OWNER);
        ISafeOwnable(address(diamond)).acceptOwnership();
        assertEq(IERC173(address(diamond)).owner(), NEW_OWNER);
        assertEq(
            ISafeOwnable(address(diamond)).nomineeOwner(),
            address(0),
            "nominee cleared post-accept"
        );
    }

    function test_acceptOwnership_revertsForNonNominee() public {
        _buildDiamond();
        IERC173(address(diamond)).transferOwnership(NEW_OWNER);
        vm.prank(RANDOM_EOA);
        vm.expectRevert(ISafeOwnableInternal.SafeOwnable__NotNomineeOwner.selector);
        ISafeOwnable(address(diamond)).acceptOwnership();
    }

    function test_transferOwnership_revertsForNonOwner() public {
        _buildDiamond();
        vm.prank(RANDOM_EOA);
        vm.expectRevert(IOwnableInternal.Ownable__NotOwner.selector);
        IERC173(address(diamond)).transferOwnership(NEW_OWNER);
    }

    // --- 9. requireOwner / requireOwnerOrPassthrough auth helpers ---------

    function test_requireOwner_passesForOwner() public {
        _buildDiamond();
        // Static call -- should not revert.
        IAdmin(address(diamond)).requireOwner(deployer);
    }

    function test_requireOwner_revertsForOther() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).requireOwner(RANDOM_EOA);
    }

    function test_requireOwnerOrPassthrough_passesForOwner() public {
        _buildDiamond();
        IAdmin(address(diamond)).requireOwnerOrPassthrough(deployer);
    }

    function test_requireOwnerOrPassthrough_passesForPassthrough() public {
        _buildDiamond();
        address fakePassthrough = address(0x9001);
        _markPassthrough(fakePassthrough);
        IAdmin(address(diamond)).requireOwnerOrPassthrough(fakePassthrough);
    }

    function test_requireOwnerOrPassthrough_revertsForOther() public {
        _buildDiamond();
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        IAdmin(address(diamond)).requireOwnerOrPassthrough(RANDOM_EOA);
    }

    function test_ownerRotation_propagatesToAdminFacetChecks() public {
        _buildDiamond();
        IERC173(address(diamond)).transferOwnership(NEW_OWNER);
        vm.prank(NEW_OWNER);
        ISafeOwnable(address(diamond)).acceptOwnership();

        // Old owner's mutation now reverts.
        vm.expectRevert(IAdmin.NotAuthorized.selector);
        vm.prank(deployer);
        IAdmin(address(diamond)).addComposeHash(HASH_A);

        // New owner's mutation succeeds.
        vm.prank(NEW_OWNER);
        IAdmin(address(diamond)).addComposeHash(HASH_A);
        assertTrue(IClusterView(address(diamond)).allowedComposeHashes(HASH_A));
    }

    // --- 10. Diamond version surfaces --------------------------------------

    function test_clusterVersion_returns4OnFreshDiamond() public {
        _buildDiamond();
        assertEq(IAdmin(address(diamond)).clusterVersion(), 4);
    }

    function test_facetBundleHash_isStableForUntouchedDiamond() public {
        _buildDiamond();
        bytes32 a = IAdmin(address(diamond)).facetBundleHash();
        bytes32 b = IAdmin(address(diamond)).facetBundleHash();
        assertEq(a, b, "deterministic for unchanged facets");
        assertTrue(a != bytes32(0), "non-zero");
    }

    function test_facetBundleHash_changesAfterCut() public {
        _buildDiamond();
        bytes32 before = IAdmin(address(diamond)).facetBundleHash();

        // Replace ViewFacet's `clusterId()` selector with a fresh ViewFacet
        // instance -- same bytecode, different deployed address. The facets
        // tuple includes facet target addresses, so the bundle hash changes.
        ViewFacet newView = new ViewFacet();
        IERC2535DiamondCutInternal.FacetCut[] memory cuts =
            new IERC2535DiamondCutInternal.FacetCut[](1);
        bytes4[] memory sel = new bytes4[](1);
        sel[0] = ViewFacet.clusterId.selector;
        cuts[0] = IERC2535DiamondCutInternal.FacetCut({
            target: address(newView),
            action: IERC2535DiamondCutInternal.FacetCutAction.REPLACE,
            selectors: sel
        });
        IERC2535DiamondCut(address(diamond)).diamondCut(cuts, address(0), "");

        bytes32 afterCut = IAdmin(address(diamond)).facetBundleHash();
        assertTrue(before != afterCut, "facet bundle hash diverges after replace");
    }
}

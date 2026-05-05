// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {OwnableStorage} from "@solidstate/contracts/access/ownable/OwnableStorage.sol";

import {ControlPlaneFacet} from "src/facets/ControlPlaneFacet.sol";
import {ControlPlaneStorage} from "src/storage/ControlPlaneStorage.sol";
import {ControlPlaneEnvelope} from "src/libraries/ControlPlaneEnvelope.sol";
import {BitmapNonces} from "src/libraries/BitmapNonces.sol";
import {CoreStorage} from "src/storage/CoreStorage.sol";
import {LifecycleStorage} from "src/storage/LifecycleStorage.sol";

// ─────────────────────────────────────────────────────────────────────
// Mock harnesses
// ─────────────────────────────────────────────────────────────────────

/// @notice Mock IERC1271 implementor used as the cluster-owner Safe.
///         Returns the magic value (`0x1626ba7e`) only when the
///         presented hash matches a pre-stashed digest AND the
///         supplied signature byte slice equals the pre-stashed
///         expected payload. Anything else returns a wrong magic
///         value (which the facet treats as `BadOwnerSig`).
/// @dev    The dual key (digest + signature payload) lets us write
///         tests that assert "the same digest, but different sig
///         bytes, fails" — important because the facet's owner check
///         is a thin EIP-1271 staticcall that does not verify the
///         signature itself.
contract MockSafe is IERC1271 {
    bytes4 internal constant MAGIC = 0x1626ba7e;

    bytes32 public expectedHash;
    bytes32 public expectedSigHash;

    /// @notice Approve a (hash, sig) pair for subsequent
    ///         `isValidSignature` calls.
    function approve(bytes32 hash_, bytes calldata sig) external {
        expectedHash = hash_;
        expectedSigHash = keccak256(sig);
    }

    /// @notice Drop the approval — `isValidSignature` returns 0xffffffff.
    function clear() external {
        expectedHash = bytes32(0);
        expectedSigHash = bytes32(0);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (hash == expectedHash && keccak256(signature) == expectedSigHash) {
            return MAGIC;
        }
        return 0xffffffff;
    }
}

/// @notice Mock for the nested 2-deep Safe scenario: inner is itself
///         an EIP-1271 verifier (a `MockSafe`), and this outer Safe
///         delegates `isValidSignature` to the inner one. Validates
///         that the facet's owner check works against a deeply nested
///         contract signature without any special-casing — stock Safe
///         + CompatibilityFallbackHandler at v1.4.1 has the same
///         delegate shape, just with quorum logic on top.
/// @dev    The nesting in production is "ClusterOwnerSafe (1-of-2:
///         AdminSafe + ClusterUsersSafe), ClusterUsersSafe being itself
///         a Safe owned by HubSafe + user wallets" — so the
///         contract-signature wrap can be 2 deep before hitting EOA
///         leaves. This mock exercises exactly that wrap depth.
contract NestedMockSafe is IERC1271 {
    IERC1271 public inner;

    constructor(IERC1271 inner_) {
        inner = inner_;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return inner.isValidSignature(hash, signature);
    }
}

/// @notice Test host that mounts the `ControlPlaneFacet` via inheritance.
///         The facet's storage lives at fixed ERC-7201 slots so it co-
///         exists cleanly with our test-only setup helpers — we just
///         need a contract whose storage we control to mirror what a
///         live diamond would hold (clusterId, owner, registered
///         members, lifecycle flags). Inheriting bypasses the diamond
///         dispatch entirely; the facet's external functions are
///         callable directly on this address.
contract ControlPlaneHost is ControlPlaneFacet {
    /// @notice Set the cluster's `string clusterId` in CoreStorage.
    function setClusterId(string calldata id) external {
        CoreStorage.layout().clusterId = id;
    }

    /// @notice Set the cluster owner Safe (or EOA) address — the
    ///         EIP-1271 endpoint the facet's `submitControl` calls into.
    function setOwner(address newOwner) external {
        OwnableStorage.layout().owner = newOwner;
    }

    /// @notice Register a synthetic member in CoreStorage. Skips the
    ///         full sig-chain verification of the real `register`
    ///         entrypoint — this is unit-test setup only. Mirrors
    ///         what `CoreFacet.register` would write: members map +
    ///         derivedToMember reverse map.
    function registerSyntheticMember(bytes32 memberId, address derivedAddr) external {
        CoreStorage.Layout storage cs = CoreStorage.layout();
        CoreStorage.Member storage m = cs.members[memberId];
        m.derivedAddr = derivedAddr;
        m.registeredAt = block.timestamp;
        cs.derivedToMember[derivedAddr] = memberId;
    }

    /// @notice Mark the cluster destroyed (Lifecycle storage). Pairs
    ///         with `whenNotDestroyed` to test the destroyed-cluster
    ///         seal.
    function setDestroyed() external {
        LifecycleStorage.layout().destroyedAt = block.timestamp;
    }

    /// @notice Mark a member retired (Lifecycle storage).
    function retireMember(bytes32 memberId) external {
        LifecycleStorage.layout().memberRetiredAt[memberId] = block.timestamp;
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

/// @title ControlPlaneFacetTest
/// @notice Behavioural coverage for the Phase A1+A2 ControlPlane facet.
///         Mirrors the spec §5.5 + §5.8 validation tables row-for-row,
///         plus the §5.7 hole-via-rebroadcast scenario.
/// @dev    Tests deploy a `ControlPlaneHost` whose own storage backs
///         the facet's ERC-7201 namespaces. A `MockSafe` sits at the
///         host's `OwnableStorage.owner` slot and approves specific
///         (digest, sig) pairs. The 2-deep nested-Safe path uses a
///         `NestedMockSafe` wrapping an inner `MockSafe` — same
///         approval shape, one extra delegation hop.
contract ControlPlaneFacetTest is Test {
    using ControlPlaneEnvelope for ControlPlaneEnvelope.ControlEnvelope;

    string internal constant CLUSTER_ID = "test-cluster-cp";
    bytes32 internal CLUSTER_ID_HASH;

    ControlPlaneHost internal host;
    MockSafe internal ownerSafe;

    address internal memberAddr;
    uint256 internal memberPk;
    bytes32 internal memberId;

    // ─── Setup ────────────────────────────────────────────────────

    function setUp() public {
        CLUSTER_ID_HASH = keccak256(bytes(CLUSTER_ID));

        host = new ControlPlaneHost();
        ownerSafe = new MockSafe();

        host.setClusterId(CLUSTER_ID);
        host.setOwner(address(ownerSafe));

        // Make a deterministic TEE-derived member EOA for receipt
        // tests. `vm.createWallet` returns a (privateKey, address) pair
        // we can later sign with via `vm.sign`. The memberId is fixed
        // independent of the address so the test is stable across
        // local/CI Foundry forge versions.
        VmSafe.Wallet memory w = vm.createWallet("teesql-cp-test-member");
        memberAddr = w.addr;
        memberPk = w.privateKey;
        memberId = keccak256(abi.encode("member-v1", memberAddr));
        host.registerSyntheticMember(memberId, memberAddr);
    }

    // ─── submitControl: happy path ────────────────────────────────

    function test_SubmitControl_HappyPath_Accepts_AndEmits() public {
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory sig = bytes("safe-sig-bytes-1");
        ownerSafe.approve(digest, sig);

        vm.expectEmit(true, true, true, true, address(host));
        emit ControlPlaneFacet.ControlInstructionBroadcast(
            env.instructionId,
            env.clusterId,
            env.nonce,
            env.targetMembers,
            env.expiry,
            env.salt,
            keccak256(env.ciphertext),
            env.ciphertext
        );

        host.submitControl(env, sig);

        assertTrue(host.isNonceUsed(env.nonce), "nonce should be marked used");
        assertEq(uint256(host.highestNonceSeen()), uint256(env.nonce), "highestNonceSeen advances");
    }

    // ─── submitControl: per-row revert table from §5.5 ───────────

    function test_SubmitControl_WrongCluster_Reverts() public {
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        env.clusterId = bytes32(uint256(0xDEAD));
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory sig = bytes("safe-sig-wrong-cluster");
        ownerSafe.approve(digest, sig);

        vm.expectRevert(ControlPlaneFacet.WrongCluster.selector);
        host.submitControl(env, sig);
    }

    function test_SubmitControl_WrongChain_Reverts() public {
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        env.chainId = block.chainid + 1;
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory sig = bytes("safe-sig-wrong-chain");
        ownerSafe.approve(digest, sig);

        vm.expectRevert(ControlPlaneFacet.WrongChain.selector);
        host.submitControl(env, sig);
    }

    function test_SubmitControl_Expired_Reverts() public {
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        env.expiry = uint64(block.timestamp);
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory sig = bytes("safe-sig-expired");
        ownerSafe.approve(digest, sig);

        vm.expectRevert(ControlPlaneFacet.EnvelopeExpired.selector);
        host.submitControl(env, sig);
    }

    function test_SubmitControl_ExactlyAtExpiry_Reverts() public {
        // Strict inequality: expiry == block.timestamp must reject.
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        vm.warp(env.expiry);
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory sig = bytes("safe-sig-exact-expiry");
        ownerSafe.approve(digest, sig);

        vm.expectRevert(ControlPlaneFacet.EnvelopeExpired.selector);
        host.submitControl(env, sig);
    }

    function test_SubmitControl_BadOwnerSig_WrongSigner_Reverts() public {
        // Approval on a DIFFERENT digest than the envelope's; the
        // staticcall to the owner Safe returns 0xffffffff → BadOwnerSig.
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        bytes32 wrongDigest = keccak256("not-the-actual-digest");
        bytes memory sig = bytes("safe-sig-wrong-signer");
        ownerSafe.approve(wrongDigest, sig);

        vm.expectRevert(ControlPlaneFacet.BadOwnerSig.selector);
        host.submitControl(env, sig);
    }

    function test_SubmitControl_BadOwnerSig_CorruptedSig_Reverts() public {
        // Approval is for one signature payload; we present a different
        // one. The mock Safe checks both digest AND sig hash, so this
        // simulates a corrupted Safe signature blob.
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory approvedSig = bytes("safe-sig-approved");
        bytes memory presentedSig = bytes("safe-sig-corrupted");
        ownerSafe.approve(digest, approvedSig);

        vm.expectRevert(ControlPlaneFacet.BadOwnerSig.selector);
        host.submitControl(env, presentedSig);
    }

    function test_SubmitControl_OwnerIsEOA_RevertsAsBadOwnerSig() public {
        // EOAs do not implement EIP-1271. The staticcall returns no
        // data; the facet must collapse this to BadOwnerSig (not bubble
        // a low-level revert or success).
        host.setOwner(address(0x1234567890123456789012345678901234567890));

        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        vm.expectRevert(ControlPlaneFacet.BadOwnerSig.selector);
        host.submitControl(env, bytes("any-sig"));
    }

    // ─── submitControl: replay + window ──────────────────────────

    function test_SubmitControl_Replay_Reverts() public {
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory sig = bytes("safe-sig-replay-test");
        ownerSafe.approve(digest, sig);

        host.submitControl(env, sig);

        // Same envelope, same digest, same sig — but the bitmap rejects
        // the second attempt. BitmapNonces' NonceAlreadyUsed bubbles up
        // unchanged from the facet.
        vm.expectRevert(abi.encodeWithSelector(BitmapNonces.NonceAlreadyUsed.selector, env.nonce));
        host.submitControl(env, sig);
    }

    function test_SubmitControl_OutOfWindow_Reverts() public {
        // Push the high-water mark to 300, then try to submit at nonce
        // 44 (which is exactly at the floor: 300 - 256 = 44).
        ControlPlaneEnvelope.ControlEnvelope memory envHigh = _baseEnvelope();
        envHigh.nonce = 300;
        _approveAndSubmit(envHigh, bytes("approve-300"));

        ControlPlaneEnvelope.ControlEnvelope memory envLow = _baseEnvelope();
        envLow.nonce = 44;
        bytes32 digest = ControlPlaneEnvelope.digest(envLow, address(host));
        bytes memory sig = bytes("approve-out-of-window");
        ownerSafe.approve(digest, sig);

        vm.expectRevert(abi.encodeWithSelector(BitmapNonces.NonceOutOfWindow.selector, uint64(44), uint64(300)));
        host.submitControl(envLow, sig);
    }

    // ─── submitControl: §5.7 hole-via-rebroadcast ────────────────

    function test_SubmitControl_HoleResolutionByRebroadcast() public {
        // Submit nonces 5, 7, 8 in order; the indexer would then have
        // a hole at 6. The cluster-owner re-signs at nonce 6 and
        // submits — facet accepts because 6 is still in-window
        // (8 - 6 = 2, well below 256). All four are then `isUsed`,
        // and `highestNonceSeen` stays pinned at 8 (the actual peak).
        uint64[4] memory nonces = [uint64(5), uint64(7), uint64(8), uint64(6)];
        for (uint256 i = 0; i < nonces.length; i++) {
            ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
            env.nonce = nonces[i];
            _approveAndSubmit(env, abi.encodePacked("hole-fill-", uint256(nonces[i])));
        }

        assertEq(uint256(host.highestNonceSeen()), 8, "highestNonceSeen pegged at peak");
        for (uint256 i = 0; i < nonces.length; i++) {
            assertTrue(host.isNonceUsed(nonces[i]), "all four nonces should be used");
        }
        assertFalse(host.isNonceUsed(4), "neighbour 4 must remain unused");
        assertFalse(host.isNonceUsed(9), "neighbour 9 must remain unused");
    }

    // ─── submitControl: nested 2-deep Safe ────────────────────────

    function test_SubmitControl_Nested2DeepSafe_Accepts() public {
        // Replace the cluster-owner Safe with a NestedMockSafe whose
        // inner is itself an EIP-1271 verifier. The facet does the
        // outermost staticcall; the outer Safe forwards to the inner;
        // inner returns the magic value. The facet does not need to
        // know about the wrap depth.
        MockSafe innerSafe = new MockSafe();
        NestedMockSafe outerSafe = new NestedMockSafe(IERC1271(address(innerSafe)));
        host.setOwner(address(outerSafe));

        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory sig = bytes("nested-2-deep-sig");

        // Approval lives on the INNERMOST Safe; the outer just
        // proxies the staticcall through.
        innerSafe.approve(digest, sig);

        host.submitControl(env, sig);

        assertTrue(host.isNonceUsed(env.nonce), "nested-2-deep accepted nonce");
    }

    // ─── submitControl: destroyed cluster is sealed ──────────────

    function test_SubmitControl_DestroyedCluster_Reverts() public {
        host.setDestroyed();
        ControlPlaneEnvelope.ControlEnvelope memory env = _baseEnvelope();
        // Pre-approve so the failure reason is destruction, not auth.
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        bytes memory sig = bytes("any-sig");
        ownerSafe.approve(digest, sig);

        vm.expectRevert(ControlPlaneFacet.ClusterDestroyed_.selector);
        host.submitControl(env, sig);
    }

    // ─── submitReceipt: happy path ────────────────────────────────

    function test_SubmitReceipt_HappyPath_Accepts_AndEmits() public {
        bytes32 instructionId = bytes32(uint256(0xA1));
        bytes32 jobId = bytes32(uint256(0xB2));
        uint8 status = 1; // ACCEPTED
        uint64 seq = 1;
        bytes32 logPointer = bytes32(0);
        bytes memory summary = bytes("");

        bytes memory sig = _signReceipt(memberPk, instructionId, jobId, status, seq, logPointer, summary);

        vm.expectEmit(true, true, true, true, address(host));
        emit ControlPlaneFacet.ControlAck(instructionId, jobId, memberId, status, seq, logPointer, summary);

        vm.prank(memberAddr);
        host.submitReceipt(instructionId, jobId, status, seq, logPointer, summary, sig);

        assertTrue(host.isJobSeen(memberId, instructionId), "job seen flag set");
        assertEq(uint256(host.receiptCount()), 1, "receiptCount bumped");
    }

    // ─── submitReceipt: revert table ─────────────────────────────

    function test_SubmitReceipt_NonMemberSender_Reverts() public {
        bytes32 instructionId = bytes32(uint256(0xA1));
        bytes32 jobId = bytes32(uint256(0xB2));
        uint8 status = 1;
        uint64 seq = 1;
        bytes32 logPointer = bytes32(0);
        bytes memory summary = bytes("");

        // Sign with a NON-registered keypair. msg.sender is also the
        // non-registered address, so derivedToMember returns 0 →
        // NotCurrentMember.
        VmSafe.Wallet memory stranger = vm.createWallet("teesql-cp-test-stranger");
        bytes memory sig = _signReceipt(stranger.privateKey, instructionId, jobId, status, seq, logPointer, summary);

        vm.prank(stranger.addr);
        vm.expectRevert(ControlPlaneFacet.NotCurrentMember.selector);
        host.submitReceipt(instructionId, jobId, status, seq, logPointer, summary, sig);
    }

    function test_SubmitReceipt_BadMemberSig_Reverts() public {
        bytes32 instructionId = bytes32(uint256(0xA1));
        bytes32 jobId = bytes32(uint256(0xB2));
        uint8 status = 1;
        uint64 seq = 1;
        bytes32 logPointer = bytes32(0);
        bytes memory summary = bytes("");

        // Sign with a DIFFERENT keypair than the registered member —
        // msg.sender is the registered member's address (so passes the
        // membership lookup), but the signature recovers to a stranger.
        // → BadMemberSig.
        VmSafe.Wallet memory stranger = vm.createWallet("teesql-cp-test-stranger-sig");
        bytes memory sig = _signReceipt(stranger.privateKey, instructionId, jobId, status, seq, logPointer, summary);

        vm.prank(memberAddr);
        vm.expectRevert(ControlPlaneFacet.BadMemberSig.selector);
        host.submitReceipt(instructionId, jobId, status, seq, logPointer, summary, sig);
    }

    function test_SubmitReceipt_Replay_Reverts() public {
        bytes32 instructionId = bytes32(uint256(0xA1));
        bytes32 jobId = bytes32(uint256(0xB2));
        uint8 status = 1;
        uint64 seq = 1;
        bytes32 logPointer = bytes32(0);
        bytes memory summary = bytes("");

        bytes memory sig = _signReceipt(memberPk, instructionId, jobId, status, seq, logPointer, summary);
        vm.prank(memberAddr);
        host.submitReceipt(instructionId, jobId, status, seq, logPointer, summary, sig);

        // Same (memberId, instructionId, jobId, seq) — replay rejected
        // by the per-(memberId, instructionId) seen-set, regardless of
        // sig validity.
        vm.prank(memberAddr);
        vm.expectRevert(ControlPlaneFacet.ReceiptAlreadySeen.selector);
        host.submitReceipt(instructionId, jobId, status, seq, logPointer, summary, sig);
    }

    function test_SubmitReceipt_ZeroSeq_Reverts() public {
        bytes32 instructionId = bytes32(uint256(0xA1));
        bytes32 jobId = bytes32(uint256(0xB2));
        uint8 status = 1;
        uint64 seq = 0;
        bytes32 logPointer = bytes32(0);
        bytes memory summary = bytes("");

        bytes memory sig = _signReceipt(memberPk, instructionId, jobId, status, seq, logPointer, summary);

        vm.prank(memberAddr);
        vm.expectRevert(ControlPlaneFacet.BadReceiptSeq.selector);
        host.submitReceipt(instructionId, jobId, status, seq, logPointer, summary, sig);
    }

    function test_SubmitReceipt_RetiredMember_Reverts() public {
        // After retirement the member's lifecycle row blocks new
        // receipt submissions even though the derivedToMember lookup
        // still resolves.
        host.retireMember(memberId);

        bytes32 instructionId = bytes32(uint256(0xA1));
        bytes32 jobId = bytes32(uint256(0xB2));
        uint8 status = 1;
        uint64 seq = 1;
        bytes32 logPointer = bytes32(0);
        bytes memory summary = bytes("");
        bytes memory sig = _signReceipt(memberPk, instructionId, jobId, status, seq, logPointer, summary);

        vm.prank(memberAddr);
        vm.expectRevert(ControlPlaneFacet.NotCurrentMember.selector);
        host.submitReceipt(instructionId, jobId, status, seq, logPointer, summary, sig);
    }

    function test_SubmitReceipt_DestroyedCluster_Reverts() public {
        host.setDestroyed();

        bytes32 instructionId = bytes32(uint256(0xA1));
        bytes32 jobId = bytes32(uint256(0xB2));
        uint8 status = 1;
        uint64 seq = 1;
        bytes32 logPointer = bytes32(0);
        bytes memory summary = bytes("");
        bytes memory sig = _signReceipt(memberPk, instructionId, jobId, status, seq, logPointer, summary);

        vm.prank(memberAddr);
        vm.expectRevert(ControlPlaneFacet.ClusterDestroyed_.selector);
        host.submitReceipt(instructionId, jobId, status, seq, logPointer, summary, sig);
    }

    // ─── Storage slot self-check ──────────────────────────────────

    function test_StorageSlot_MatchesERC7201Derivation() public pure {
        // Lock the storage slot literal against the ERC-7201
        // derivation formula. Drift between the namespace string in
        // the comment and the constant fails this test loudly.
        bytes32 expected = keccak256(abi.encode(uint256(keccak256("teesql.storage.Cluster.ControlPlane")) - 1))
            & ~bytes32(uint256(0xff));
        assertEq(ControlPlaneStorage.SLOT, expected, "ControlPlane SLOT must match ERC-7201 derivation");
    }

    // ─── Helpers ──────────────────────────────────────────────────

    /// @dev Build a base envelope tied to this host. Each test mutates
    ///      a single field to isolate one validation rule. `chainId`
    ///      is locked to `block.chainid` (Foundry default 31337) so
    ///      the envelope passes step 2 unless explicitly mutated.
    function _baseEnvelope() internal view returns (ControlPlaneEnvelope.ControlEnvelope memory env) {
        bytes32[] memory targets = new bytes32[](1);
        targets[0] = bytes32(uint256(0x111));
        env = ControlPlaneEnvelope.ControlEnvelope({
            clusterId: CLUSTER_ID_HASH,
            targetMembers: targets,
            instructionId: bytes32(uint256(0xABCDEF)),
            nonce: 1,
            chainId: block.chainid,
            expiry: uint64(block.timestamp + 3600),
            salt: bytes32(uint256(0xCAFEBABE)),
            ciphertext: hex"deadbeef"
        });
    }

    /// @dev Approve `(digest(env), sig)` on `ownerSafe` and submit.
    ///      Used by tests that don't care about the digest plumbing
    ///      itself, only the post-condition.
    function _approveAndSubmit(ControlPlaneEnvelope.ControlEnvelope memory env, bytes memory sig) internal {
        bytes32 digest = ControlPlaneEnvelope.digest(env, address(host));
        ownerSafe.approve(digest, sig);
        host.submitControl(env, sig);
    }

    /// @dev Sign a receipt with the given private key, EIP-191 wrapped.
    ///      The digest construction must match the facet's
    ///      `_receiptDigest` verbatim (spec §5.8). Locked here so a
    ///      drift in either side fails the receipt-recovery test.
    function _signReceipt(
        uint256 pk,
        bytes32 instructionId,
        bytes32 jobId,
        uint8 status,
        uint64 seq,
        bytes32 logPointer,
        bytes memory summary
    ) internal view returns (bytes memory) {
        bytes32 inner = keccak256(
            abi.encode(
                "teesql-control-receipt:v1",
                block.chainid,
                address(host),
                CLUSTER_ID_HASH,
                instructionId,
                jobId,
                status,
                seq,
                logPointer,
                keccak256(summary)
            )
        );
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }
}


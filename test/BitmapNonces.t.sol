// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {BitmapNonces} from "src/libraries/BitmapNonces.sol";

/// @notice Thin harness that exposes the library's `internal`
///         entrypoints as `external` calls. Required because
///         `vm.expectRevert` from forge-std matches a revert at the
///         next call depth — internal library functions inline into
///         the test contract and don't open a call frame, so reverts
///         from inlined calls don't satisfy the cheatcode. Wrapping
///         in an external call (the harness) restores the call
///         boundary the cheatcode expects.
contract BitmapNoncesHarness {
    BitmapNonces.Layout internal layout;

    function markUsed(uint64 nonce) external returns (bool) {
        return BitmapNonces.markUsed(layout, nonce);
    }

    function isUsed(uint64 nonce) external view returns (bool) {
        return BitmapNonces.isUsed(layout, nonce);
    }

    function lastNonce() external view returns (uint64) {
        return layout.lastNonce;
    }
}

/// @title BitmapNoncesTest
/// @notice Behavioural tests for the bitmap-windowed nonce store.
///         Mirrors the semantics enumerated in
///         `docs/specs/control-plane-redesign.md` §5.2: monotonic
///         high-water mark, in-window out-of-order acceptance,
///         replay rejection, far-below-window rejection, and the
///         word-boundary corner.
/// @dev    The library operates on `storage`, so this test routes
///         through `BitmapNoncesHarness` rather than holding the
///         layout directly. The harness is the call-frame boundary
///         `vm.expectRevert` needs to observe.
contract BitmapNoncesTest is Test {
    BitmapNoncesHarness internal nonces;

    function setUp() public {
        nonces = new BitmapNoncesHarness();
    }

    // ─── First-ever marks + sequential ────────────────────────────

    function test_FirstMark_Succeeds_AndAdvances() public {
        bool advanced = nonces.markUsed(1);
        assertTrue(advanced, "first mark must advance lastNonce");
        assertEq(uint256(nonces.lastNonce()), 1, "lastNonce should be 1");
        assertTrue(nonces.isUsed(1), "isUsed(1) should be true");
        assertFalse(nonces.isUsed(2), "isUsed(2) should be false");
    }

    function test_Sequential_2Through10_AllAdvance() public {
        for (uint64 n = 1; n <= 10; n++) {
            bool advanced = nonces.markUsed(n);
            assertTrue(advanced, "sequential mark must advance");
            assertTrue(nonces.isUsed(n), "isUsed should be true after mark");
        }
        assertEq(uint256(nonces.lastNonce()), 10, "lastNonce should be 10");
        // Sanity: an unmarked low nonce reads false.
        assertFalse(nonces.isUsed(0), "unmarked nonce 0 reads false");
    }

    // ─── Out-of-order in-window ───────────────────────────────────

    function test_OutOfOrder_HighThenLow_BothSucceed() public {
        bool advancedHigh = nonces.markUsed(20);
        assertTrue(advancedHigh, "20 advances from 0");
        assertEq(uint256(nonces.lastNonce()), 20);

        bool advancedLow = nonces.markUsed(15);
        assertFalse(advancedLow, "15 lands behind 20 - must NOT advance");
        assertEq(uint256(nonces.lastNonce()), 20, "lastNonce stays at 20");
        assertTrue(nonces.isUsed(15));
        assertTrue(nonces.isUsed(20));
    }

    // ─── Replay ───────────────────────────────────────────────────

    function test_Replay_Reverts() public {
        nonces.markUsed(5);
        vm.expectRevert(abi.encodeWithSelector(BitmapNonces.NonceAlreadyUsed.selector, uint64(5)));
        nonces.markUsed(5);
    }

    function test_Replay_AfterAdvance_StillReverts() public {
        nonces.markUsed(5);
        nonces.markUsed(50);
        vm.expectRevert(abi.encodeWithSelector(BitmapNonces.NonceAlreadyUsed.selector, uint64(5)));
        nonces.markUsed(5);
    }

    // ─── Window edge ──────────────────────────────────────────────
    //
    // Per spec §5.2: nonce <= lastNonce - 256 is rejected. With
    // lastNonce == 300:
    //   * markUsed(44) rejects   (300 - 44 = 256, equal to floor)
    //   * markUsed(45) succeeds  (300 - 45 = 255, just inside window)

    function test_WindowEdge_AtFloor_Reverts() public {
        _advanceLastTo(300);
        vm.expectRevert(abi.encodeWithSelector(BitmapNonces.NonceOutOfWindow.selector, uint64(44), uint64(300)));
        nonces.markUsed(44);
    }

    function test_WindowEdge_JustInside_Succeeds() public {
        _advanceLastTo(300);
        bool advanced = nonces.markUsed(45);
        assertFalse(advanced, "45 lands behind 300 - must NOT advance");
        assertTrue(nonces.isUsed(45));
        assertEq(uint256(nonces.lastNonce()), 300);
    }

    function test_FarBelow_Reverts() public {
        _advanceLastTo(1000);
        vm.expectRevert(abi.encodeWithSelector(BitmapNonces.NonceOutOfWindow.selector, uint64(1), uint64(1000)));
        nonces.markUsed(1);
    }

    // ─── Below 256 → no underflow ─────────────────────────────────
    //
    // Confirms the `last >= 256` guard short-circuits the unchecked
    // window arithmetic when we have not yet seen 256 nonces.

    function test_LowLast_AnyNonceAccepted_NoUnderflow() public {
        // markUsed(255) advances; markUsed(0) is in-window
        // (0 > 255 - 256 underflows-but-is-guarded) and lands
        // BEHIND the high-water mark, so it must NOT advance.
        nonces.markUsed(255);
        bool advanced = nonces.markUsed(0);
        assertFalse(advanced, "0 lands behind 255 - must NOT advance");
        assertTrue(nonces.isUsed(0));
        assertEq(uint256(nonces.lastNonce()), 255, "lastNonce should remain 255");
    }

    // ─── Bitmap word boundary ─────────────────────────────────────
    //
    // Nonces straddling `nonce % 256 == 255 → 0` must round-trip.
    // 255 sits at bit 255 of word 0, 256 sits at bit 0 of word 1 —
    // a missed shift would alias them. Both must be markable
    // independently and read back as set.

    function test_WordBoundary_Straddle_BothSet() public {
        nonces.markUsed(255);
        nonces.markUsed(256);
        nonces.markUsed(257);

        assertTrue(nonces.isUsed(255), "bit 255 of word 0");
        assertTrue(nonces.isUsed(256), "bit 0 of word 1");
        assertTrue(nonces.isUsed(257), "bit 1 of word 1");
        assertEq(uint256(nonces.lastNonce()), 257);
    }

    function test_WordBoundary_NoAliasing() public {
        // 255 (word 0, bit 255) must not appear set after marking
        // 256 (word 1, bit 0). Catches a `>> 256`-style off-by-one
        // that would alias bit indices into the same word.
        nonces.markUsed(256);
        assertFalse(nonces.isUsed(255), "marking 256 must not mark 255");
        assertFalse(nonces.isUsed(0), "marking 256 must not mark 0");
        assertTrue(nonces.isUsed(256));
    }

    // ─── Helper ───────────────────────────────────────────────────
    //
    // Forces `lastNonce` to a target without emitting hundreds of
    // bitmap-bit writes. We only need ONE high mark to advance the
    // high-water mark; the bits below remain unset, which is the
    // realistic state of a long-lived window where most slots have
    // not been observed.

    function _advanceLastTo(uint64 target) internal {
        nonces.markUsed(target);
    }
}

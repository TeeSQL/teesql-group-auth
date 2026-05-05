// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BitmapNonces
/// @notice Bitmap-windowed nonce acceptance store. Supports out-of-order
///         delivery within a 256-nonce window relative to `lastNonce`,
///         giving O(1) set + check while bounding storage churn.
/// @dev    Designed for the ControlPlane facet (see
///         `docs/specs/control-plane-redesign.md` §5.2). Each cluster
///         keeps one `Layout` in ERC-7201 storage and the facet calls
///         `markUsed` from `submitControl`; `lastNonce` advances
///         monotonically as the facet observes higher-numbered envelopes.
///
///         Window semantics (matches the spec verbatim):
///           * Initial `lastNonce == 0` and the bitmap is empty.
///           * `markUsed(nonce)` reverts with `NonceOutOfWindow` when
///             `lastNonce >= 256 && nonce <= lastNonce - 256`.
///             Equivalently: an envelope further than 256 nonces below
///             the high-water mark is permanently rejected.
///           * `markUsed(nonce)` reverts with `NonceAlreadyUsed` when
///             the bit for `nonce` is already set.
///           * Otherwise the bit is set; if `nonce > lastNonce` the
///             high-water mark advances and the function returns
///             `true`. If the call landed strictly inside the window
///             without advancing, it returns `false`.
///
///         Gas trade-off: when `lastNonce` advances past the next
///         word boundary (i.e. `nonce / 256` increases) the older
///         word(s) below the new floor become permanently dead but
///         are *not* zeroed. Zeroing yields a small refund on the
///         word in question but costs a `SSTORE` per pruned slot,
///         and at 256-nonce steady-state churn that nets out to a
///         loss. Leaving the dead words in place is the documented
///         choice; consumers must not assume `bitmap` is sparse.
///
///         The library is pure mechanics — there is no notion of
///         signature, sender, or chain. Pairs cleanly with
///         `ControlPlaneEnvelope.digest()` for the surface that
///         actually authorises the nonce-bearing message.
library BitmapNonces {
    /// @notice Per-cluster window state. Stored under the ControlPlane
    ///         ERC-7201 namespace (see `ControlPlaneStorage` in §5.2).
    struct Layout {
        /// @notice Highest nonce ever marked used. The window is the
        ///         half-open range `(lastNonce - 256, lastNonce]` once
        ///         `lastNonce >= 256`; when smaller, the lower bound
        ///         clamps at zero.
        uint64 lastNonce;
        /// @notice `nonce / 256` → 256-bit word, bit `nonce % 256`.
        mapping(uint256 => uint256) bitmap;
    }

    /// @notice The supplied nonce is below `lastNonce - 256` and is
    ///         therefore outside the acceptance window.
    error NonceOutOfWindow(uint64 nonce, uint64 lastNonce);

    /// @notice The bit for `nonce` is already set in the bitmap.
    error NonceAlreadyUsed(uint64 nonce);

    /// @notice Pure read of the bitmap bit for `nonce`. Returns true
    ///         iff `nonce` was previously passed to `markUsed`. Does
    ///         NOT consider the window — a nonce below the floor was
    ///         either marked-then-overwritten (impossible with the
    ///         current API), or never marked. Callers that care about
    ///         the window must check `nonce <= lastNonce - 256`
    ///         separately.
    /// @dev    Provided as a view to let off-chain tooling / other
    ///         facets observe acceptance state without paying a
    ///         storage write to assert it.
    function isUsed(Layout storage l, uint64 nonce) internal view returns (bool) {
        uint256 word = l.bitmap[uint256(nonce) >> 8];
        return (word >> (uint256(nonce) & 0xff)) & 1 == 1;
    }

    /// @notice Mark `nonce` as used. Reverts on out-of-window or
    ///         replay. Returns `true` iff `lastNonce` advanced as a
    ///         result of this call (i.e. `nonce > lastNonce` on
    ///         entry); `false` if the call filled in a hole inside
    ///         the existing window.
    function markUsed(Layout storage l, uint64 nonce) internal returns (bool advanced) {
        uint64 last = l.lastNonce;
        // Window check: only meaningful once `last >= 256`. Below
        // that point every non-negative nonce is in-window. The
        // unchecked subtraction is safe because of the explicit
        // `last >= 256` guard.
        if (last >= 256) {
            unchecked {
                if (nonce <= last - 256) revert NonceOutOfWindow(nonce, last);
            }
        }

        uint256 wordIdx = uint256(nonce) >> 8;
        uint256 bitIdx = uint256(nonce) & 0xff;
        uint256 mask = uint256(1) << bitIdx;

        uint256 word = l.bitmap[wordIdx];
        if (word & mask != 0) revert NonceAlreadyUsed(nonce);
        l.bitmap[wordIdx] = word | mask;

        if (nonce > last) {
            l.lastNonce = nonce;
            advanced = true;
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDstackAttestationAdapter} from "../../interfaces/IDstackAttestationAdapter.sol";
import {IBootGate} from "../../interfaces/IBootGate.sol";
import {IAdmin} from "../../interfaces/IAdmin.sol";
import {IAppAuth} from "../../IAppAuth.sol";
import {AttestationDstackStorage} from "../../storage/AttestationDstackStorage.sol";

/// @title DstackAttestationAdapterFacet
/// @notice Diamond facet implementing the dstack TEE-runtime attestation
///         adapter. Owns `teesql.storage.Attestation.Dstack` namespace.
/// @dev    Selectors namespaced `dstack_*` per spec §13.1. Cross-facet logic
///         hops via same-diamond dispatch (`address(this)`) per §13.4.
///         Adapter id pinned in spec §19.1.
contract DstackAttestationAdapterFacet is IDstackAttestationAdapter {
    /// @notice keccak256("teesql.attestation.dstack") — pinned in spec §19.1.
    bytes32 public constant DSTACK_ATTESTATION_ID =
        0x33a9d6b17861ebd35aca9a68779e7b913c04060dc2f6ab672d9f190a13924d80;

    /// @notice keccak256("UpToDate") — precomputed for cheap tcbStatus comparison.
    bytes32 private constant UP_TO_DATE_HASH = keccak256(bytes("UpToDate"));

    // --- Events ---
    event RequireTcbUpToDateSet(bool value);

    // --- Errors ---
    /// @notice Selector intentionally unimplemented for dstack runtime today.
    ///         Reverted to fail loudly on accidental dispatch.
    error NotImplemented();

    // ─── dstack_* namespaced surface ───────────────────────────────────────
    // No un-namespaced selectors per spec §13.1 — they would collide on
    // the diamond if a second runtime adapter were added.

    function dstack_attestationId() external pure override returns (bytes32) {
        return DSTACK_ATTESTATION_ID;
    }

    /// @dev Per spec §6.4:
    ///      1. Pull cluster-wide checks via same-diamond BootGate dispatch.
    ///      2. Add dstack-runtime-specific TCB check (when enabled).
    ///      3. Return `(true, "")` on pass.
    function dstack_isAppAllowed(IAppAuth.AppBootInfo calldata b)
        external
        view
        override
        returns (bool ok, string memory reason)
    {
        (bool ok1, string memory r1) =
            IBootGate(address(this)).clusterBootPolicy(b.appId, b.composeHash, b.deviceId);
        if (!ok1) {
            return (false, r1);
        }

        if (AttestationDstackStorage.layout().requireTcbUpToDate) {
            if (keccak256(bytes(b.tcbStatus)) != UP_TO_DATE_HASH) {
                return (false, "tcb not up to date");
            }
        }

        return (true, "");
    }

    function dstack_onMemberMinted(address /* passthrough */) external pure override {
        // No-op for the dstack runtime today. Selector exists for symmetry
        // with future runtimes that may need a runtime-side mint hook
        // (e.g., to register a per-CVM quote with a runtime-local registry).
        // Returning silently lets CoreFacet.createMember dispatch to it
        // unconditionally without per-runtime branching at the call site.
        return;
    }

    /// @dev Owner-or-passthrough authorization via same-diamond AdminFacet dispatch.
    function dstack_setRequireTcbUpToDate(bool v) external override {
        IAdmin(address(this)).requireOwnerOrPassthrough(msg.sender);
        AttestationDstackStorage.layout().requireTcbUpToDate = v;
        emit RequireTcbUpToDateSet(v);
    }

    function dstack_requireTcbUpToDate() external view override returns (bool) {
        return AttestationDstackStorage.layout().requireTcbUpToDate;
    }

    function dstack_version() external pure override returns (uint256) {
        return 1;
    }
}

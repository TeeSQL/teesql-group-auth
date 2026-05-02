// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAppAuth} from "../IAppAuth.sol";

/// @title IDstackAttestationAdapter
/// @notice DstackAttestationAdapterFacet's external surface. ALL selectors
///         carry the `dstack_*` prefix per spec §13.1 — no un-namespaced
///         methods, so multiple per-runtime adapter facets can coexist on
///         the same diamond without collision. Adapter id pinned in spec §19.1:
///         `keccak256("teesql.attestation.dstack")`.
/// @dev    The conceptual `IAttestationAdapter` shape (see spec §9.1) is a
///         documentation contract only — never inherited at the Solidity
///         level, since uniform-shape inheritance would force selector
///         collisions across runtimes.
interface IDstackAttestationAdapter {
    /// Stable runtime identifier. Namespaced selector lives on the diamond.
    function dstack_attestationId() external pure returns (bytes32);

    /// Boot gate entry point. DstackKms calls IAppAuth(passthrough).isAppAllowed,
    /// DstackMember forwards to dstack_isAppAllowed. Combines cluster-wide
    /// BootGate checks with dstack-runtime-specific policy.
    function dstack_isAppAllowed(IAppAuth.AppBootInfo calldata b)
        external view returns (bool ok, string memory reason);

    /// Optional mint hook — selector exists for symmetry. dstack runtime has
    /// no work today; reverts if called inappropriately.
    function dstack_onMemberMinted(address passthrough) external;

    // dstack-runtime-specific policy
    function dstack_setRequireTcbUpToDate(bool v) external;
    function dstack_requireTcbUpToDate() external view returns (bool);

    // Adapter facet's own version counter
    function dstack_version() external pure returns (uint256);
}

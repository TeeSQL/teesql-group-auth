// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SolidStateDiamond} from "@solidstate/contracts/proxy/diamond/SolidStateDiamond.sol";

/// @title ClusterDiamond
/// @notice Per-cluster ERC-2535 proxy. Inherits the solidstate diamond
///         base, which wires up `diamondCut` (DiamondWritable), the loupe
///         (DiamondReadable: `facets`, `facetFunctionSelectors`,
///         `facetAddresses`, `facetAddress`), `supportsInterface`
///         (ERC165Base), the fallback dispatcher (DiamondBase +
///         DiamondFallback), and a `SafeOwnable` 2-step owner transfer for
///         the diamondCut authority itself.
/// @dev    Atomic bring-up: this constructor takes the application
///         facet-cut list + an init contract + init calldata and runs
///         the cut + initialization DELEGATECALL inside its own ctor
///         frame, before returning. This matches spec §11.2 step 2
///         ("solidstate's Diamond constructor takes the cut + init in
///         one tx") even though the upstream `SolidStateDiamond`
///         constructor itself takes no arguments — we layer the
///         application cut on top via `_diamondCut`. The result: every
///         user-facing selector in the diamond is registered atomically
///         in the deploy tx; the diamond is never reachable in a
///         "constructor done, no facets attached" intermediate state.
///
///         There are TWO distinct owners on a cluster:
///
///         1. **Solidstate owner** (this contract's `owner()` /
///            `transferOwnership` / `acceptOwnership` selectors, exposed
///            by `SolidStateDiamond`). Gated on `OwnableInternal`. The
///            ONLY caller authorized to invoke `diamondCut`. Set to
///            `msg.sender` in the parent constructor — i.e., the
///            deployer at construction time. The deployer must
///            `transferOwnership` to the cluster Safe immediately after
///            bring-up; the Safe then `acceptOwnership` and assumes
///            sole authority over future facet swaps.
///
///         2. **Cluster owner** (lives in the `Cluster.Core` ERC-7201
///            namespace, set by `DiamondInit.init` and exposed via
///            `AdminFacet.owner`). The provider-agnostic governance
///            authority for cluster-wide selectors (allowlists, pause,
///            adapter registration, lifecycle). Read by every facet's
///            `requireOwner`-style gate. Read by `DstackMember`'s
///            `_authorizeUpgrade` to gate per-member UUPS upgrades.
///
///         In production both roles are typically the same Safe, but
///         they are intentionally separate selectors backed by separate
///         slots so the trust boundaries stay reviewable.
///         Transferring one does NOT transfer the other — the deployer
///         runbook MUST cover both.
///
///         The cluster's per-runtime adapter selection lives in
///         `Cluster.AdapterRegistry`; per-cluster boot policy lives in
///         `Cluster.Allowlists`; lifecycle (destroy / retire) lives in
///         `Cluster.Lifecycle`. None of those namespaces are touched by
///         the proxy itself — they are populated atomically by
///         `DiamondInit` via the constructor's init hook below.
///
///         Spec: `cluster-v4-diamond-and-member-uups.md` §3, §11.2,
///         §13.4.
contract ClusterDiamond is SolidStateDiamond {
    /// Atomically wire the application facets and run the per-cluster
    /// init contract. The parent `SolidStateDiamond` constructor first
    /// registers the built-in selectors (DiamondCut, loupe, ERC-165,
    /// SafeOwnable) and `_setOwner(msg.sender)` — only AFTER that does
    /// the call below land, so `_diamondCut` sees a fully-initialized
    /// diamond and the `target.delegatecall(data)` inside `_initialize`
    /// runs in the diamond's own storage context.
    constructor(FacetCut[] memory facetCuts, address init, bytes memory initCalldata) SolidStateDiamond() {
        _diamondCut(facetCuts, init, initCalldata);
    }
}

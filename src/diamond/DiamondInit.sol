// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OwnableStorage} from "@solidstate/contracts/access/ownable/OwnableStorage.sol";

import {CoreStorage} from "../storage/CoreStorage.sol";
import {AdapterRegistryStorage} from "../storage/AdapterRegistryStorage.sol";
import {KmsDstackStorage} from "../storage/KmsDstackStorage.sol";

/// @title DiamondInit
/// @notice One-shot init contract DELEGATECALLed by `ClusterDiamond`'s
///         constructor (spec §11.2). Populates the per-cluster initial
///         state spanning multiple ERC-7201 namespaces atomically:
///         identity + governance (`Cluster.Core`), the two-axis adapter
///         registry seed (`Cluster.AdapterRegistry`), and the
///         dstack-KMS bootstrap state (`Kms.Dstack`).
/// @dev    Caller is responsible for ensuring the matching facet cuts (the
///         `facetCuts` array passed to the diamond constructor) actually
///         include the dstack attestation + KMS adapter facet selectors —
///         this contract only writes the registry pointers and trusts the
///         selectors will resolve at call time. Spec §13.2 ("init-contract
///         discipline for `Add` cuts") covers reviewer obligations on
///         every future `Add` cut that brings in a new stateful facet.
///         Future stateful adapters extend this template's `init` shape
///         (or ship a peer init contract) — see spec §11.2 + §13.2.
contract DiamondInit {
    error ZeroAddress();

    struct InitArgs {
        // Cluster identity + governance (Cluster.Core)
        address owner;
        address pauser;
        string clusterId;
        address factory;
        // dstack-KMS bootstrap state (Kms.Dstack)
        address dstackKms;
        address[] dstackKmsRoots;
        // Two-axis adapter registration (Cluster.AdapterRegistry).
        // Caller MUST match these to the facetCuts list passed into the
        // diamond constructor — see spec §13.2.
        bytes32 dstackAttestationId;
        address dstackAttestationFacet;
        bytes32 dstackKmsId;
        address dstackKmsFacet;
    }

    /// One-shot initializer. Invoked exactly once via DELEGATECALL from the
    /// diamond's constructor (or from a later `diamondCut` whose `_init`
    /// argument points at a fresh `DiamondInit` if a future cluster needs
    /// re-initialization for an added stateful facet — see spec §13.2).
    function init(InitArgs calldata args) external {
        if (
            args.owner == address(0) ||
            args.pauser == address(0) ||
            args.factory == address(0) ||
            args.dstackKms == address(0) ||
            args.dstackAttestationFacet == address(0) ||
            args.dstackKmsFacet == address(0)
        ) revert ZeroAddress();

        // ── Cluster ownership ──────────────────────────────────────────────
        // SolidStateDiamond's constructor set OwnableStorage.owner = msg.sender
        // (the deployer). Overwrite to the operator-specified owner so that
        // ownership is in its final state before this constructor returns —
        // the deployer no longer owns the diamond after init completes.
        OwnableStorage.layout().owner = args.owner;

        // ── Cluster identity + factory + version ───────────────────────────
        CoreStorage.Layout storage core = CoreStorage.layout();
        core.pauser = args.pauser;
        core.clusterId = args.clusterId;
        core.factory = args.factory;
        // v4 cutover — spec §16. AdminFacet bumps this on every diamondCut
        // thereafter.
        core.clusterVersion = 4;

        // ── Two-axis adapter registry ──────────────────────────────────────
        AdapterRegistryStorage.Layout storage reg = AdapterRegistryStorage.layout();

        reg.attestationFacet[args.dstackAttestationId] = args.dstackAttestationFacet;
        reg.attestationRegistered[args.dstackAttestationId] = true;
        reg.attestationIds.push(args.dstackAttestationId);
        reg.defaultAttestationId = args.dstackAttestationId;

        reg.kmsFacet[args.dstackKmsId] = args.dstackKmsFacet;
        reg.kmsRegistered[args.dstackKmsId] = true;
        reg.kmsIds.push(args.dstackKmsId);
        reg.defaultKmsId = args.dstackKmsId;

        // ── dstack-KMS bootstrap state ─────────────────────────────────────
        KmsDstackStorage.Layout storage kms = KmsDstackStorage.layout();
        kms.kms = args.dstackKms;
        for (uint256 i = 0; i < args.dstackKmsRoots.length; i++) {
            if (args.dstackKmsRoots[i] == address(0)) revert ZeroAddress();
            kms.allowedKmsRoots[args.dstackKmsRoots[i]] = true;
        }
    }
}

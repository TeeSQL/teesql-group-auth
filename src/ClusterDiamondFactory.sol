// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDiamondWritableInternal} from "@solidstate/contracts/proxy/diamond/writable/IDiamondWritableInternal.sol";

import {IClusterDiamondFactory} from "./interfaces/IClusterDiamondFactory.sol";
import {ClusterDiamond} from "./diamond/ClusterDiamond.sol";
import {ClusterFactoryStorage} from "./storage/ClusterFactoryStorage.sol";

/// @title ClusterDiamondFactory
/// @notice Chain-singleton factory that deploys `ClusterDiamond` proxies
///         and records each one in a permanent provenance map. Webhook
///         (`isDeployedCluster`) + hub fleet enumeration (`listClusters`)
///         consume this map.
/// @dev    Spec: `cluster-diamond-factory-and-member-provenance.md`. Admin
///         (`Ownable2Step`) starts as the deployer EOA at chain-bootstrap
///         time and can be transferred to a Safe via
///         `transferAdmin` / `acceptAdmin` when the operator is ready.
///         `deployCluster` is `onlyAdmin` to close the registry-spam
///         attack — a permissionless `deployCluster` would let any
///         caller pollute `registeredClusters[]` with attacker-
///         controlled stranded diamonds for ~$300 of gas, breaking hub
///         fleet enumeration and forcing the webhook to lean entirely
///         on the defense-in-depth `cluster.isOurPassthrough` check.
contract ClusterDiamondFactory is IClusterDiamondFactory {
    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();
        ClusterFactoryStorage.layout().admin = _admin;
    }

    modifier onlyAdmin() {
        if (msg.sender != ClusterFactoryStorage.layout().admin) revert NotAdmin();
        _;
    }

    // ── Reads ──────────────────────────────────────────────────────────────

    function admin() external view returns (address) {
        return ClusterFactoryStorage.layout().admin;
    }

    function pendingAdmin() external view returns (address) {
        return ClusterFactoryStorage.layout().pendingAdmin;
    }

    function isDeployedCluster(address diamond) external view returns (bool) {
        return ClusterFactoryStorage.layout().deployedClusters[diamond];
    }

    function listClusters() external view returns (address[] memory) {
        return ClusterFactoryStorage.layout().registeredClusters;
    }

    function clusterCount() external view returns (uint256) {
        return ClusterFactoryStorage.layout().registeredClusters.length;
    }

    // ── Ownable2Step admin transfer ────────────────────────────────────────

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        ClusterFactoryStorage.layout().pendingAdmin = newAdmin;
        emit AdminTransferStarted(ClusterFactoryStorage.layout().admin, newAdmin);
    }

    function acceptAdmin() external {
        ClusterFactoryStorage.Layout storage s = ClusterFactoryStorage.layout();
        if (msg.sender != s.pendingAdmin) revert NotPendingAdmin();
        address previous = s.admin;
        s.admin = s.pendingAdmin;
        s.pendingAdmin = address(0);
        emit AdminTransferred(previous, s.admin);
    }

    // ── Deploy ─────────────────────────────────────────────────────────────

    /// Deploy a `ClusterDiamond`. The cluster's actual governance is
    /// whatever `DiamondInit.init(args)` writes into `OwnableStorage`
    /// during the constructor's init DELEGATECALL — independent of
    /// factory admin (typically the same Safe in practice).
    ///
    /// Salt enables CREATE2-deterministic addresses; pass `bytes32(0)`
    /// for plain CREATE.
    function deployCluster(
        IDiamondWritableInternal.FacetCut[] memory facetCuts,
        address init,
        bytes memory initCalldata,
        bytes32 salt
    ) external onlyAdmin returns (address diamond) {
        if (init == address(0)) revert ZeroAddress();

        if (salt == bytes32(0)) {
            diamond = address(new ClusterDiamond(facetCuts, init, initCalldata));
        } else {
            diamond = address(new ClusterDiamond{salt: salt}(facetCuts, init, initCalldata));
        }

        ClusterFactoryStorage.Layout storage s = ClusterFactoryStorage.layout();
        s.deployedClusters[diamond] = true;
        s.registeredClusters.push(diamond);

        emit ClusterDeployed(diamond, msg.sender, salt);
    }
}

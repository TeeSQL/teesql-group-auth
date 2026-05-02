// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDiamondWritableInternal} from "@solidstate/contracts/proxy/diamond/writable/IDiamondWritableInternal.sol";

/// @title IClusterDiamondFactory
/// @notice External surface for the chain-singleton `ClusterDiamondFactory`.
///         Admin-gated `deployCluster` mints `ClusterDiamond` proxies and
///         records each one in `deployedClusters[]` for downstream
///         provenance reads (gas-sponsorship webhook, hub fleet
///         enumeration). Mirrors `IClusterMemberFactory`'s shape.
interface IClusterDiamondFactory {
    event ClusterDeployed(address indexed diamond, address indexed deployer, bytes32 indexed salt);
    event AdminTransferStarted(address indexed previousAdmin, address indexed newAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    error NotAdmin();
    error ZeroAddress();
    error NotPendingAdmin();

    // Reads
    function admin() external view returns (address);
    function pendingAdmin() external view returns (address);
    /// True iff `diamond` was minted by this factory's `deployCluster`.
    /// False for externally-deployed cluster diamonds at the same
    /// address (defends against a rogue contract claiming to be one of
    /// our clusters).
    function isDeployedCluster(address diamond) external view returns (bool);
    function listClusters() external view returns (address[] memory);
    function clusterCount() external view returns (uint256);

    // Ownable2Step admin transfer
    function transferAdmin(address newAdmin) external;
    function acceptAdmin() external;

    // Deploy
    function deployCluster(
        IDiamondWritableInternal.FacetCut[] memory facetCuts,
        address init,
        bytes memory initCalldata,
        bytes32 salt
    ) external returns (address diamond);
}

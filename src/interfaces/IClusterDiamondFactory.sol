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

    // UUPS lifecycle. Constructor is empty (only `_disableInitializers`);
    // proxy calls `initialize` once at chain-bootstrap. `reinitialize` is
    // a placeholder per the repo UUPS convention — v1 reverts; future
    // impl revisions override with `reinitializer(N)` and migration
    // logic, then ship via `upgradeToAndCall(newImpl, encodeCall(reinitialize, (N, data)))`.
    function initialize(address admin) external;
    function reinitialize(uint64 version, bytes calldata data) external;

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

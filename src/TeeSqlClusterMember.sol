// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAppAuth} from "./IAppAuth.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title TeeSqlClusterMember
/// @notice Per-CVM passthrough that forwards IAppAuth.isAppAllowed to a TeeSqlClusterApp.
/// @dev No mutable storage, no admin, no upgrade path. Exists only to give each CVM a unique
///      address usable as its DstackKms `app_id`. All logic and state live on the cluster
///      contract. `cluster` is an immutable baked into bytecode at construction.
contract TeeSqlClusterMember is IAppAuth {
    /// @notice The TeeSqlClusterApp this passthrough routes to.
    address public immutable cluster;

    error ClusterZero();

    constructor(address _cluster) {
        if (_cluster == address(0)) revert ClusterZero();
        cluster = _cluster;
    }

    /// @inheritdoc IAppAuth
    /// @dev Called by DstackKms during CVM boot with `bootInfo.appId == address(this)`.
    ///      We forward unchanged; the cluster validates compose hash, device id, and
    ///      defensively checks `isOurPassthrough[bootInfo.appId]`.
    function isAppAllowed(AppBootInfo calldata bootInfo)
        external
        view
        override
        returns (bool isAllowed, string memory reason)
    {
        return IAppAuth(cluster).isAppAllowed(bootInfo);
    }

    function supportsInterface(bytes4 id) external pure override returns (bool) {
        return id == type(IAppAuth).interfaceId || id == type(IERC165).interfaceId;
    }
}

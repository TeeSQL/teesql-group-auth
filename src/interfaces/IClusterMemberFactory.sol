// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IClusterMemberFactory
/// @notice External surface for the chain-singleton ClusterMemberFactory.
///         Per-runtime memberImpl mapping; Member proxies are ERC1967Proxy
///         instances deployed via CREATE2 with the runtime-matched impl.
interface IClusterMemberFactory {
    event MemberImplUpdated(bytes32 indexed attestationId, address indexed oldImpl, address indexed newImpl);
    event MemberDeployed(
        address indexed cluster,
        bytes32 indexed salt,
        bytes32 indexed attestationId,
        address proxy,
        address impl
    );
    event AdminTransferStarted(address indexed previousAdmin, address indexed newAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    error NotAdmin();
    error ZeroAddress();
    error ImplUnchanged();
    error ImplNotRegistered();
    error ImplDriftDetected();
    error NotPendingAdmin();

    // Reads
    function memberImpl(bytes32 attestationId) external view returns (address);
    function admin() external view returns (address);
    function pendingAdmin() external view returns (address);
    function registeredAttestationIds() external view returns (bytes32[] memory);
    /// True iff `proxy` was minted by this factory's `deployMember`. False
    /// for externally-deployed proxies at the same address. Webhook +
    /// hub fleet enumeration consume this.
    function isDeployedMember(address proxy) external view returns (bool);

    // Per-runtime impl management
    function setMemberImpl(bytes32 attestationId, address newImpl) external;

    // Ownable2Step admin transfer
    function transferAdmin(address newAdmin) external;
    function acceptAdmin() external;

    // Deploy
    function deployMember(address cluster, bytes32 salt, bytes32 attestationId)
        external returns (address proxy);
    function predict(address cluster, bytes32 salt, bytes32 attestationId)
        external view returns (address);
    function deployMemberWithExpectedImpl(
        address cluster,
        bytes32 salt,
        bytes32 attestationId,
        address expectedImpl
    ) external returns (address proxy);
}

/// @notice Initializer interface the Member proxy's `initialize` must satisfy.
interface IMemberInit {
    function initialize(address cluster) external;
}

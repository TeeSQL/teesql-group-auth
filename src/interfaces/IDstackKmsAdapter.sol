// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IDstackKmsAdapter
/// @notice DstackKmsAdapterFacet's external surface. ALL selectors carry
///         the `dstack_kms_*` prefix per spec §13.1 — no un-namespaced
///         methods, so multiple per-KMS adapter facets can coexist on the
///         same diamond without collision. KMS id pinned in spec §19.1:
///         `keccak256("teesql.kms.dstack")`.
/// @dev    The conceptual `IKmsAdapter` shape (see spec §9.2) is a
///         documentation contract only — never inherited at the Solidity
///         level, since uniform-shape inheritance would force selector
///         collisions across KMSs.
interface IDstackKmsAdapter {
    /// Stable KMS identifier. Namespaced selector lives on the diamond.
    function dstack_kms_id() external pure returns (bytes32);

    /// Sig-chain verification. Core calls this from register() with the
    /// dstack-shaped Proof ABI-encoded into bytes. Decodes internally.
    function dstack_kms_verifySigChain(bytes calldata proof)
        external
        view
        returns (bytes32 codeId, bytes memory derivedPubkey);

    /// Mint hook — Core calls this from createMember(). dstack-KMS impl
    /// invokes IDstackKms(kms).registerApp(passthrough).
    function dstack_kms_registerApp(address passthrough) external;

    // KMS pointer + root allowlist mgmt
    function dstack_kms_setKms(address kms) external;
    function dstack_kms_kms() external view returns (address);
    function dstack_kms_addRoot(address root) external;
    function dstack_kms_removeRoot(address root) external;
    function dstack_kms_allowedRoots(address root) external view returns (bool);

    function dstack_kms_version() external pure returns (uint256);
}

/// @notice Minimal interface for the dstack-KMS contract we register
///         passthroughs against. Mirrored from dstack/kms/auth-eth.
interface IDstackKms {
    function registerApp(address appId) external;
    function registeredApps(address appId) external view returns (bool);
}

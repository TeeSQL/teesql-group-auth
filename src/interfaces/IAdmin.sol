// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAdmin
/// @notice AdminFacet's external surface — cluster-wide governance.
/// @dev    All selectors are bare (un-namespaced) — they're provider-agnostic.
///         Per-runtime/per-KMS admin lives on the matching adapter facet
///         under `<provider>_*` / `<provider>_kms_*` namespaces.
interface IAdmin {
    // --- Events ---
    event PauserSet(address indexed pauser);
    event ComposeHashAdded(bytes32 composeHash);
    event ComposeHashRemoved(bytes32 composeHash);
    event DeviceAdded(bytes32 deviceId);
    event DeviceRemoved(bytes32 deviceId);
    event AllowAnyDeviceSet(bool allowAny);
    event SignerAuthorized(address indexed signer, uint8 permissions);
    event SignerRevoked(address indexed signer);
    event AttestationAdapterRegistered(bytes32 indexed attestationId, address indexed facet);
    event AttestationAdapterDeregistered(bytes32 indexed attestationId);
    event KmsAdapterRegistered(bytes32 indexed kmsId, address indexed facet);
    event KmsAdapterDeregistered(bytes32 indexed kmsId);
    event DefaultAttestationSet(bytes32 indexed attestationId);
    event DefaultKmsSet(bytes32 indexed kmsId);

    // --- Errors ---
    error NotAuthorized();
    error ZeroAddress();
    error BadPerms();
    error AlreadyRegistered();
    error NotRegistered();

    // Ownership lives in solidstate's SafeOwnable (pre-registered on the
    // diamond by SolidStateDiamond's constructor). The owner / transferOwnership /
    // acceptOwnership / nomineeOwner selectors are dispatched directly through
    // the diamond — IAdmin doesn't redeclare them. AdminFacet's auth helpers
    // below (requireOwner / requireOwnerOrPassthrough) read the same
    // OwnableStorage slot for consistency.

    // --- Pause (cluster-wide) ---
    function pauser() external view returns (address);
    function setPauser(address newPauser) external;
    function pause() external;
    function unpause() external;
    function paused() external view returns (bool);

    // --- Cluster-wide allowlists (writes Cluster.Allowlists) ---
    function addComposeHash(bytes32 h) external;
    function removeComposeHash(bytes32 h) external;
    function addDevice(bytes32 d) external;
    function removeDevice(bytes32 d) external;
    function setAllowAnyDevice(bool v) external;
    function authorizeSigner(address signer, uint8 permissions) external;
    function revokeSigner(address signer) external;

    // --- Two-axis adapter management ---
    function registerAttestationAdapter(bytes32 attestationId, address facet) external;
    function deregisterAttestationAdapter(bytes32 attestationId) external;
    function setDefaultAttestationAdapter(bytes32 attestationId) external;
    function registerKmsAdapter(bytes32 kmsId, address facet) external;
    function deregisterKmsAdapter(bytes32 kmsId) external;
    function setDefaultKmsAdapter(bytes32 kmsId) external;

    // --- Lifecycle ---
    function destroy() external;
    function retireMember(bytes32 memberId) external;

    // --- Diamond version surfaces ---
    function clusterVersion() external view returns (uint256);
    function facetBundleHash() external view returns (bytes32);

    // --- Auth helpers (callable by other facets via diamond dispatch) ---
    function requireOwner(address caller) external view;
    function requireOwnerOrPassthrough(address caller) external view;
}

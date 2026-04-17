// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {IVerifier} from "./IVerifier.sol";

/// @title TEEBridge
/// @notice Multi-verifier TEE membership registry. Platform-agnostic —
///         verifiers (dstack, Nitro, SEV, Sigstore, ...) implement IVerifier
///         and attest that a caller is a genuine TEE running approved code.
/// @dev    Forked from sxysun's TEEBridge at github.com/Account-Link/tee-interop,
///         wrapped in UUPS+Ownable so we can upgrade under our Safe+Timelock
///         governance.
contract TEEBridge is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    // --- Storage ---

    /// @notice Registered per-platform verifiers. Admin maintains the set.
    mapping(address => bool) public allowedVerifiers;

    /// @notice Allowed code identities (compose hash / app_id).
    mapping(bytes32 => bool) public allowedCode;

    struct Member {
        bytes32 codeId;
        address verifier;
        bytes pubkey;
        bytes userData;
        uint256 registeredAt;
    }
    /// @dev memberId = keccak256(pubkey)
    mapping(bytes32 => Member) internal _members;

    struct OnboardMsg {
        bytes32 fromMember;
        bytes encryptedPayload;
    }
    mapping(bytes32 => OnboardMsg[]) internal _onboarding;

    /// @notice Database authorization for cluster access
    /// @dev clusterId => signerAddress => AuthorizedSigner struct
    mapping(bytes32 => mapping(address => AuthorizedSigner)) public authorizedSigners;

    struct AuthorizedSigner {
        uint8 permissions;     // Bitfield: 1=read, 2=write (3=read+write)
        bool active;           // Whether the authorization is currently active
        uint256 authorizedAt;  // Timestamp when authorization was granted
    }

    // --- Events ---

    event MemberRegistered(
        bytes32 indexed memberId,
        bytes32 indexed codeId,
        address indexed verifier,
        bytes pubkey,
        bytes userData
    );
    event OnboardingPosted(bytes32 indexed toMember, bytes32 indexed fromMember);
    event AllowedCodeAdded(bytes32 indexed codeId);
    event AllowedCodeRemoved(bytes32 indexed codeId);
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);
    event SignerAuthorized(bytes32 indexed clusterId, address indexed signer, uint8 permissions);
    event SignerRevoked(bytes32 indexed clusterId, address indexed signer);

    // --- Errors ---

    error VerifierNotAllowed();
    error CodeNotAllowed();
    error AlreadyRegistered();
    error MemberNotFound();
    error ZeroAddress();

    // --- Initializer ---

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param _owner Owner address — intended to be our Safe (+ timelock).
    /// @param _verifiers Initial set of allowed verifier contracts.
    /// @param _allowedCodes Initial set of allowed code ids (compose hashes).
    function initialize(
        address _owner,
        address[] calldata _verifiers,
        bytes32[] calldata _allowedCodes
    ) external initializer {
        if (_owner == address(0)) revert ZeroAddress();
        __Ownable_init(_owner);

        for (uint256 i = 0; i < _verifiers.length; i++) {
            if (_verifiers[i] == address(0)) revert ZeroAddress();
            allowedVerifiers[_verifiers[i]] = true;
            emit VerifierAdded(_verifiers[i]);
        }

        for (uint256 i = 0; i < _allowedCodes.length; i++) {
            allowedCode[_allowedCodes[i]] = true;
            emit AllowedCodeAdded(_allowedCodes[i]);
        }
    }

    // --- Admin ---

    function addVerifier(address verifier) external onlyOwner {
        if (verifier == address(0)) revert ZeroAddress();
        allowedVerifiers[verifier] = true;
        emit VerifierAdded(verifier);
    }

    function removeVerifier(address verifier) external onlyOwner {
        allowedVerifiers[verifier] = false;
        emit VerifierRemoved(verifier);
    }

    function addAllowedCode(bytes32 codeId) external onlyOwner {
        allowedCode[codeId] = true;
        emit AllowedCodeAdded(codeId);
    }

    function removeAllowedCode(bytes32 codeId) external onlyOwner {
        allowedCode[codeId] = false;
        emit AllowedCodeRemoved(codeId);
    }

    // --- Registration ---

    /// @notice Register a member. The verifier validates the proof; on success
    ///         the caller is recorded with the derived pubkey reported by the
    ///         verifier. memberId = keccak256(pubkey).
    function register(address verifier, bytes calldata proof) external returns (bytes32) {
        if (!allowedVerifiers[verifier]) revert VerifierNotAllowed();
        (bytes32 codeId, bytes memory pubkey, bytes memory userData) =
            IVerifier(verifier).verifyAndCache(proof);
        if (!allowedCode[codeId]) revert CodeNotAllowed();

        bytes32 memberId = keccak256(pubkey);
        if (_members[memberId].registeredAt != 0) revert AlreadyRegistered();
        _members[memberId] = Member({
            codeId: codeId,
            verifier: verifier,
            pubkey: pubkey,
            userData: userData,
            registeredAt: block.timestamp
        });
        emit MemberRegistered(memberId, codeId, verifier, pubkey, userData);
        return memberId;
    }

    // --- Onboarding ---

    /// @notice Post an ECIES-encrypted payload from one member to another.
    ///         Used to distribute cluster secrets (replication credentials,
    ///         backup encryption keys) to newly-joined members.
    function onboard(bytes32 fromMemberId, bytes32 toMemberId, bytes calldata encryptedPayload) external {
        if (_members[fromMemberId].registeredAt == 0) revert MemberNotFound();
        if (_members[toMemberId].registeredAt == 0) revert MemberNotFound();
        _onboarding[toMemberId].push(OnboardMsg({fromMember: fromMemberId, encryptedPayload: encryptedPayload}));
        emit OnboardingPosted(toMemberId, fromMemberId);
    }

    // --- Database Authorization ---

    /// @notice Authorize a signer for database access to a cluster
    /// @param clusterId The cluster identifier (typically cluster name hash)
    /// @param signerAddress The Ethereum address derived from the signer's public key
    /// @param permissions Permission bitfield: 1=read, 2=write, 3=read+write
    function addAuthorizedSigner(
        bytes32 clusterId,
        address signerAddress,
        uint8 permissions
    ) external onlyOwner {
        if (signerAddress == address(0)) revert ZeroAddress();
        if (permissions == 0 || permissions > 3) {
            revert("Invalid permissions: must be 1 (read), 2 (write), or 3 (read+write)");
        }

        authorizedSigners[clusterId][signerAddress] = AuthorizedSigner({
            permissions: permissions,
            active: true,
            authorizedAt: block.timestamp
        });

        emit SignerAuthorized(clusterId, signerAddress, permissions);
    }

    /// @notice Revoke database access for a signer
    /// @param clusterId The cluster identifier
    /// @param signerAddress The signer's Ethereum address
    function revokeAuthorizedSigner(
        bytes32 clusterId,
        address signerAddress
    ) external onlyOwner {
        authorizedSigners[clusterId][signerAddress].active = false;
        emit SignerRevoked(clusterId, signerAddress);
    }

    /// @notice Check if a signer is authorized for specific permissions on a cluster
    /// @param clusterId The cluster identifier
    /// @param signerAddress The signer's Ethereum address
    /// @param requiredPermission Permission level: 1=read, 2=write, 3=read+write
    /// @return Whether the signer has the required permissions
    function isAuthorizedSigner(
        bytes32 clusterId,
        address signerAddress,
        uint8 requiredPermission
    ) external view returns (bool) {
        AuthorizedSigner storage signer = authorizedSigners[clusterId][signerAddress];

        if (!signer.active) return false;

        // Check if signer has the required permissions
        // For read (1): must have at least 1
        // For write (2): must have at least 2
        // For read+write (3): must have 3
        return (signer.permissions & requiredPermission) == requiredPermission;
    }

    /// @notice Get authorization details for a signer
    /// @param clusterId The cluster identifier
    /// @param signerAddress The signer's Ethereum address
    /// @return permissions The permission bitfield
    /// @return active Whether the authorization is active
    /// @return authorizedAt When the authorization was granted
    function getAuthorization(
        bytes32 clusterId,
        address signerAddress
    ) external view returns (uint8 permissions, bool active, uint256 authorizedAt) {
        AuthorizedSigner storage signer = authorizedSigners[clusterId][signerAddress];
        return (signer.permissions, signer.active, signer.authorizedAt);
    }

    // --- Views ---

    function getMember(bytes32 memberId)
        external
        view
        returns (bytes32 codeId, address verifier, bytes memory pubkey, bytes memory userData, uint256 registeredAt)
    {
        Member storage m = _members[memberId];
        return (m.codeId, m.verifier, m.pubkey, m.userData, m.registeredAt);
    }

    function isMember(bytes32 memberId) external view returns (bool) {
        return _members[memberId].registeredAt != 0;
    }

    function getOnboarding(bytes32 memberId) external view returns (OnboardMsg[] memory) {
        return _onboarding[memberId];
    }

    // --- UUPS ---

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

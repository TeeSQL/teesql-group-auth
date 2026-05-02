// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CoreStorage} from "../storage/CoreStorage.sol";

/// @title ICore
/// @notice CoreFacet's external surface — provider-agnostic membership and
///         leader registry, lifecycle, factory orchestration.
interface ICore {
    // --- Public types referenced in function signatures ---

    struct RegisterArgs {
        bytes proof; // Opaque to Core; KMS-adapter-specific shape
        bytes bindingSig; // EIP-191 sig from derivedAddr — provider-agnostic
        address instanceId;
        bytes endpoint;
        bytes publicEndpoint;
        string dnsLabel;
    }

    struct CallAuth {
        bytes32 memberId;
        uint256 nonce;
        bytes sig;
    }

    struct Witness {
        bytes32 voucherMemberId;
        bytes sig;
    }

    // --- Events ---
    event MemberPassthroughCreated(
        address indexed passthrough, bytes32 indexed salt, bytes32 indexed attestationId, bytes32 kmsId
    );
    event MemberRegistered(
        bytes32 indexed memberId, address indexed instanceId, address indexed passthrough, string dnsLabel
    );
    event InstanceBindingVerified(bytes32 indexed memberId, address indexed instanceId);
    event LeaderClaimed(bytes32 indexed memberId, uint256 indexed epoch, bytes endpoint);
    event EndpointUpdated(bytes32 indexed memberId, bytes endpoint);
    event PublicEndpointUpdated(bytes32 indexed memberId, bytes publicEndpoint);
    event OnboardingPosted(bytes32 indexed toMember, bytes32 indexed fromMember);
    event ClusterDestroyed(uint256 timestamp);
    event MemberRetired(bytes32 indexed memberId, uint256 timestamp);

    // --- Errors ---
    error WrongAppId();
    error InstanceBindingInvalid();
    error NotMember();
    error NotLeaderClaimant();
    error NoWitness();
    error SelfWitness();
    error WitnessNotMember();
    error DuplicateWitness();
    error BadWitnessSig();
    error BadNonce();
    error BadSig();
    error AdapterNotRegistered();
    error ClusterDestroyed_();
    error MemberRetired_();
    error AlreadyRetired();
    error CannotRetireLeader();

    // --- Membership ---
    function register(RegisterArgs calldata args) external returns (bytes32 memberId);
    function getMember(bytes32 id) external view returns (CoreStorage.Member memory);
    function instanceToMember(address) external view returns (bytes32);
    function derivedToMember(address) external view returns (bytes32);
    function passthroughToMember(address) external view returns (bytes32);
    function memberNonce(bytes32) external view returns (uint256);

    // --- Onboarding ---
    function onboard(CallAuth calldata auth, bytes32 toId, bytes calldata payload) external;
    function getOnboarding(bytes32 id) external view returns (CoreStorage.OnboardMsg[] memory);

    // --- Leader ---
    function claimLeader(CallAuth calldata auth, bytes calldata newEndpoint, Witness[] calldata witnesses) external;
    function updateEndpoint(CallAuth calldata auth, bytes calldata newEndpoint) external;
    function updatePublicEndpoint(CallAuth calldata auth, bytes calldata newPublicEndpoint) external;
    function currentLeader() external view returns (CoreStorage.Member memory);
    function leaderLease() external view returns (bytes32 memberId, uint256 epoch);

    // --- Factory orchestration ---
    function createMember(bytes32 salt, bytes32 attestationId, bytes32 kmsId) external returns (address passthrough);
    function predictMember(bytes32 salt, bytes32 attestationId) external view returns (address);
    function isOurPassthrough(address passthrough) external view returns (bool);

    // --- Per-call auth message helpers ---
    function registrationMessage(
        address instanceId,
        bytes calldata endpoint,
        bytes calldata publicEndpoint,
        string calldata dnsLabel
    ) external view returns (bytes32);
    function callMessage(bytes32 memberId, uint256 nonce, bytes4 selector, bytes memory args)
        external
        view
        returns (bytes32);
    function witnessMessage(bytes32 deposedMemberId, uint256 deposedEpoch, bytes32 voucherMemberId)
        external
        view
        returns (bytes32);

    // clusterId(), destroy(), retireMember() are part of the cluster ABI but
    // live on ViewFacet (read surface) and AdminFacet (owner-gated lifecycle)
    // respectively, NOT CoreFacet — no selector collision at the diamond.
}

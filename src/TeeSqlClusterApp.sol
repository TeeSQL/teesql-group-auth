// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IAppAuth} from "./IAppAuth.sol";
import {IAppAuthBasicManagement} from "./IAppAuthBasicManagement.sol";
import {DstackSigChain, IKmsRootRegistry} from "./DstackSigChain.sol";
import {TeeSqlClusterMember} from "./TeeSqlClusterMember.sol";

interface IDstackKms {
    function registerApp(address appId) external;
    function registeredApps(address appId) external view returns (bool);
}

/// @title TeeSqlClusterApp
/// @notice Unified cluster controller: KMS boot gate (via passthroughs), membership, onboarding,
///         signer authorization, and leader registry, all under one UUPS proxy.
contract TeeSqlClusterApp is
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    IAppAuth,
    IAppAuthBasicManagement,
    IKmsRootRegistry
{
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // --- Cluster identity ---
    string public clusterId;

    // --- KMS boot gate ---
    mapping(bytes32 => bool) public allowedComposeHashes;
    mapping(bytes32 => bool) public allowedDeviceIds;
    bool public allowAnyDevice;

    // --- Sig-chain trust anchors (IKmsRootRegistry public getter) ---
    mapping(address => bool) public override allowedKmsRoots;

    // --- Membership ---
    struct Member {
        address instanceId;
        bytes derivedPubkey;
        address derivedAddr;
        address passthrough;
        string role;
        bytes endpoint; // AES-GCM ct of tailnet IP; peer-to-peer only.
        bytes publicEndpoint; // UTF-8 public URL (Phala gateway or operator host).
        uint256 registeredAt;
    }
    mapping(bytes32 => Member) internal _members;
    mapping(address => bytes32) public instanceToMember;
    mapping(address => bytes32) public derivedToMember;
    mapping(bytes32 => uint256) public memberNonce;

    // --- Onboarding ---
    struct OnboardMsg {
        bytes32 fromMember;
        bytes encryptedPayload;
    }
    mapping(bytes32 => OnboardMsg[]) internal _onboarding;

    // --- Signer authorization (cluster-scoped) ---
    struct AuthorizedSigner {
        uint8 permissions;
        bool active;
        uint256 authorizedAt;
    }
    mapping(address => AuthorizedSigner) public authorizedSigners;

    // --- Leader lease ---
    // No TTL: leadership holds until a higher-epoch claimLeader() replaces it.
    // Liveness is proven off-chain via TEE peer-to-peer challenges; the chain
    // records only cluster shape changes.
    struct Lease {
        bytes32 memberId;
        uint256 epoch;
    }
    Lease public leaderLease;

    // --- Witness (for claimLeader) ---
    struct Witness {
        bytes32 voucherMemberId;
        bytes sig;
    }

    // --- Peering ---
    mapping(address => bool) public allowedPeerApps;

    // --- Passthrough registry ---
    mapping(address => bool) public isOurPassthrough;
    address public kms;
    uint256 public nextMemberSeq;

    // --- Events ---
    event MemberPassthroughCreated(address indexed passthrough, bytes32 indexed salt);
    event MemberRegistered(
        bytes32 indexed memberId, address indexed instanceId, address indexed passthrough, string role
    );
    event InstanceBindingVerified(bytes32 indexed memberId, address indexed instanceId);
    event LeaderClaimed(bytes32 indexed memberId, uint256 indexed epoch, bytes endpoint);
    event EndpointUpdated(bytes32 indexed memberId, bytes endpoint);
    event PublicEndpointUpdated(bytes32 indexed memberId, bytes publicEndpoint);
    event OnboardingPosted(bytes32 indexed toMember, bytes32 indexed fromMember);
    event KmsRootAdded(address indexed root);
    event KmsRootRemoved(address indexed root);
    event SignerAuthorized(address indexed signer, uint8 permissions);
    event SignerRevoked(address indexed signer);
    event PeerAppSet(address indexed peerApp, bool allowed);
    event KmsSet(address indexed kms);
    event AllowAnyDeviceSet(bool value);

    // --- Errors ---
    error VerifierFailed();
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
    error ZeroAddress();
    error BadPerms();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _pauser,
        address _kms,
        string calldata _clusterId,
        address[] calldata _kmsRoots
    ) external initializer {
        if (_owner == address(0) || _pauser == address(0) || _kms == address(0)) {
            revert ZeroAddress();
        }
        __Ownable_init(_owner);
        __AccessControl_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(PAUSER_ROLE, _pauser);

        kms = _kms;
        clusterId = _clusterId;
        emit KmsSet(_kms);

        for (uint256 i = 0; i < _kmsRoots.length; i++) {
            if (_kmsRoots[i] == address(0)) revert ZeroAddress();
            allowedKmsRoots[_kmsRoots[i]] = true;
            emit KmsRootAdded(_kmsRoots[i]);
        }
    }

    // --- Passthrough factory ---

    /// @notice CREATE2-deploy a new TeeSqlClusterMember passthrough and register it with DstackKms.
    /// @dev Permissionless: deploying a passthrough is inert until a CVM boots under it and passes
    ///      `register()`. Compose/device/KMS-root allowlists gate any effective use.
    /// @param salt Caller-provided salt; if zero, uses auto-incrementing nextMemberSeq.
    /// @return passthrough The deployed passthrough's address (= new CVM's app_id).
    function createMember(bytes32 salt) external whenNotPaused returns (address passthrough) {
        bytes32 effectiveSalt = salt == bytes32(0) ? bytes32(uint256(nextMemberSeq++)) : salt;
        passthrough = address(new TeeSqlClusterMember{salt: effectiveSalt}(address(this)));
        IDstackKms(kms).registerApp(passthrough);
        isOurPassthrough[passthrough] = true;
        emit MemberPassthroughCreated(passthrough, effectiveSalt);
    }

    /// @notice Predict a passthrough address for a given salt without deploying.
    function predictMember(bytes32 salt) external view returns (address) {
        bytes32 effectiveSalt = salt == bytes32(0) ? bytes32(uint256(nextMemberSeq)) : salt;
        bytes32 bytecodeHash =
            keccak256(abi.encodePacked(type(TeeSqlClusterMember).creationCode, abi.encode(address(this))));
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), effectiveSalt, bytecodeHash))))
        );
    }

    // --- IAppAuth (called by passthrough, which is called by DstackKms) ---
    function isAppAllowed(AppBootInfo calldata b) external view override returns (bool, string memory) {
        if (paused()) return (false, "cluster paused");
        if (!isOurPassthrough[b.appId]) return (false, "unknown passthrough");
        if (!allowedComposeHashes[b.composeHash]) return (false, "compose hash not allowed");
        if (!allowAnyDevice && !allowedDeviceIds[b.deviceId]) return (false, "device not allowed");
        return (true, "");
    }

    // --- Registration ---

    struct RegisterArgs {
        DstackSigChain.Proof sigChainProof;
        bytes bindingSig;
        address instanceId;
        string role;
        bytes endpoint;
        bytes publicEndpoint;
    }

    /// @notice Registration binding commits to every registered field so a gas relay cannot
    ///         rewrite role/endpoint/publicEndpoint/instance_id. Pins to (chainId, clusterApp) to
    ///         prevent cross-contract / cross-chain replay.
    function registrationMessage(
        address instanceId,
        string calldata role,
        bytes calldata endpoint,
        bytes calldata publicEndpoint
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                "teesql-cluster-register:v1",
                block.chainid,
                address(this),
                clusterId,
                instanceId,
                role,
                endpoint,
                publicEndpoint
            )
        );
    }

    function register(RegisterArgs calldata a) external whenNotPaused returns (bytes32 memberId) {
        // Copy proof into memory (library takes memory struct)
        DstackSigChain.Proof memory proof = a.sigChainProof;
        (bytes32 codeId, bytes memory derivedPubkey) = DstackSigChain.verify(proof, this);
        // codeId is bytes32(bytes20(app_id)) — left-aligned, consistent with
        // what dstack KMS signed over and what DstackSigChain.verify requires.
        // Take the leftmost 20 bytes, not the rightmost.
        address passthrough = address(bytes20(codeId));
        if (!isOurPassthrough[passthrough]) revert WrongAppId();

        bytes32 bindHash = registrationMessage(a.instanceId, a.role, a.endpoint, a.publicEndpoint);
        bytes32 bindEthHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", bindHash));
        address derivedAddr = DstackSigChain.compressedToAddress(derivedPubkey);
        address recovered = DstackSigChain.recover(bindEthHash, a.bindingSig);
        if (recovered != derivedAddr) revert InstanceBindingInvalid();

        memberId = keccak256(derivedPubkey);
        _members[memberId] = Member({
            instanceId: a.instanceId,
            derivedPubkey: derivedPubkey,
            derivedAddr: derivedAddr,
            passthrough: passthrough,
            role: a.role,
            endpoint: a.endpoint,
            publicEndpoint: a.publicEndpoint,
            registeredAt: block.timestamp
        });
        instanceToMember[a.instanceId] = memberId;
        derivedToMember[derivedAddr] = memberId;
        emit MemberRegistered(memberId, a.instanceId, passthrough, a.role);
        emit InstanceBindingVerified(memberId, a.instanceId);
    }

    // --- Per-call auth ---

    struct CallAuth {
        bytes32 memberId;
        uint256 nonce;
        bytes sig;
    }

    function callMessage(bytes32 memberId, uint256 nonce, bytes4 selector, bytes memory args)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                "teesql-cluster-call:v1", block.chainid, address(this), memberId, nonce, selector, keccak256(args)
            )
        );
    }

    function _verifyCall(CallAuth calldata a, bytes4 selector, bytes memory args) internal returns (bytes32) {
        Member storage m = _members[a.memberId];
        if (m.registeredAt == 0) revert NotMember();
        if (a.nonce != memberNonce[a.memberId]) revert BadNonce();

        bytes32 h = callMessage(a.memberId, a.nonce, selector, args);
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        address signer = DstackSigChain.recover(ethHash, a.sig);
        if (signer != m.derivedAddr) revert BadSig();

        unchecked {
            memberNonce[a.memberId] = a.nonce + 1;
        }
        return a.memberId;
    }

    // --- Leader lease ---

    /// @notice Canonical witness message. Voucher signs this to attest that the named
    ///         leader is offline at the given epoch. Binding to (deposedMemberId, deposedEpoch)
    ///         prevents cross-epoch replay.
    function witnessMessage(bytes32 deposedMemberId, uint256 deposedEpoch, bytes32 voucherMemberId)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                "teesql-leader-offline:v1",
                block.chainid,
                address(this),
                clusterId,
                deposedMemberId,
                deposedEpoch,
                voucherMemberId
            )
        );
    }

    /// @notice Claim leadership and publish an encrypted endpoint. First-ever claim and
    ///         self-reclaim require no witnesses; replacing another leader requires ≥1
    ///         witness from a non-claimant member attesting to the current leader being
    ///         offline at the current epoch.
    function claimLeader(CallAuth calldata auth, bytes calldata newEndpoint, Witness[] calldata witnesses)
        external
        whenNotPaused
    {
        bytes32 memberId = _verifyCall(auth, this.claimLeader.selector, abi.encode(newEndpoint, witnesses));

        bytes32 currentLeaderId = leaderLease.memberId;
        uint256 currentEpoch = leaderLease.epoch;

        if (currentLeaderId != bytes32(0) && currentLeaderId != memberId) {
            if (witnesses.length == 0) revert NoWitness();
            bytes32[] memory seen = new bytes32[](witnesses.length);
            for (uint256 i = 0; i < witnesses.length; i++) {
                bytes32 vId = witnesses[i].voucherMemberId;
                if (vId == memberId) revert SelfWitness();
                if (_members[vId].registeredAt == 0) revert WitnessNotMember();
                for (uint256 j = 0; j < i; j++) {
                    if (seen[j] == vId) revert DuplicateWitness();
                }
                seen[i] = vId;

                bytes32 wMsg = witnessMessage(currentLeaderId, currentEpoch, vId);
                bytes32 wEthHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", wMsg));
                address recovered = DstackSigChain.recover(wEthHash, witnesses[i].sig);
                if (recovered != _members[vId].derivedAddr) revert BadWitnessSig();
            }
        }

        uint256 newEpoch = currentEpoch + 1;
        leaderLease = Lease({memberId: memberId, epoch: newEpoch});
        _members[memberId].endpoint = newEndpoint;
        emit LeaderClaimed(memberId, newEpoch, newEndpoint);
    }

    /// @notice Update this member's encrypted tailnet endpoint without bumping the leader epoch.
    ///         Called by secondaries post-onboarding (once they have the cluster key) and on
    ///         tailnet-IP changes.
    function updateEndpoint(CallAuth calldata auth, bytes calldata newEndpoint) external whenNotPaused {
        bytes32 memberId = _verifyCall(auth, this.updateEndpoint.selector, abi.encode(newEndpoint));
        _members[memberId].endpoint = newEndpoint;
        emit EndpointUpdated(memberId, newEndpoint);
    }

    /// @notice Update this member's customer-facing public URL. Changes rarely — only when
    ///         a self-hosted operator changes their configured URL.
    function updatePublicEndpoint(CallAuth calldata auth, bytes calldata newPublicEndpoint) external whenNotPaused {
        bytes32 memberId = _verifyCall(auth, this.updatePublicEndpoint.selector, abi.encode(newPublicEndpoint));
        _members[memberId].publicEndpoint = newPublicEndpoint;
        emit PublicEndpointUpdated(memberId, newPublicEndpoint);
    }

    function currentLeader() external view returns (Member memory) {
        if (leaderLease.memberId == bytes32(0)) revert NotLeaderClaimant();
        return _members[leaderLease.memberId];
    }

    // --- Onboarding ---

    function onboard(CallAuth calldata auth, bytes32 toId, bytes calldata payload) external whenNotPaused {
        bytes32 fromId = _verifyCall(auth, this.onboard.selector, abi.encode(toId, payload));
        if (_members[toId].registeredAt == 0) revert NotMember();
        _onboarding[toId].push(OnboardMsg({fromMember: fromId, encryptedPayload: payload}));
        emit OnboardingPosted(toId, fromId);
    }

    // --- Admin ---

    function addComposeHash(bytes32 h) external override onlyOwner {
        allowedComposeHashes[h] = true;
        emit ComposeHashAdded(h);
    }

    function removeComposeHash(bytes32 h) external override onlyOwner {
        allowedComposeHashes[h] = false;
        emit ComposeHashRemoved(h);
    }

    function addDevice(bytes32 d) external override onlyOwner {
        allowedDeviceIds[d] = true;
        emit DeviceAdded(d);
    }

    function removeDevice(bytes32 d) external override onlyOwner {
        allowedDeviceIds[d] = false;
        emit DeviceRemoved(d);
    }

    function setAllowAnyDevice(bool v) external onlyOwner {
        allowAnyDevice = v;
        emit AllowAnyDeviceSet(v);
    }

    function addKmsRoot(address r) external onlyOwner {
        if (r == address(0)) revert ZeroAddress();
        allowedKmsRoots[r] = true;
        emit KmsRootAdded(r);
    }

    function removeKmsRoot(address r) external onlyOwner {
        allowedKmsRoots[r] = false;
        emit KmsRootRemoved(r);
    }

    function authorizeSigner(address s, uint8 p) external onlyOwner {
        if (s == address(0)) revert ZeroAddress();
        if (p == 0 || p > 3) revert BadPerms();
        authorizedSigners[s] = AuthorizedSigner(p, true, block.timestamp);
        emit SignerAuthorized(s, p);
    }

    function revokeSigner(address s) external onlyOwner {
        authorizedSigners[s].active = false;
        emit SignerRevoked(s);
    }

    function setPeerApp(address p, bool allowed) external onlyOwner {
        allowedPeerApps[p] = allowed;
        emit PeerAppSet(p, allowed);
    }

    function setKms(address k) external onlyOwner {
        if (k == address(0)) revert ZeroAddress();
        kms = k;
        emit KmsSet(k);
    }

    // --- Pause ---
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // --- Views ---
    function isSignerAuthorized(address s, uint8 required) external view returns (bool) {
        AuthorizedSigner storage a = authorizedSigners[s];
        return a.active && (a.permissions & required) == required;
    }

    function getMember(bytes32 id) external view returns (Member memory) {
        return _members[id];
    }

    function getOnboarding(bytes32 id) external view returns (OnboardMsg[] memory) {
        return _onboarding[id];
    }

    function supportsInterface(bytes4 id)
        public
        view
        virtual
        override(AccessControlUpgradeable, IERC165)
        returns (bool)
    {
        return id == type(IAppAuth).interfaceId || id == type(IAppAuthBasicManagement).interfaceId
            || super.supportsInterface(id);
    }

    // --- UUPS ---
    function _authorizeUpgrade(address) internal override onlyOwner {}

    uint256[50] private __gap;
}

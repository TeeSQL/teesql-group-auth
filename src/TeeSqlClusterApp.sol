// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
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
/// @notice Unified cluster controller: KMS boot gate (via passthroughs), membership,
///         onboarding, signer authorization, and leader registry, all under one
///         UUPS proxy.
/// @dev    State lives in a single ERC-7201 namespaced struct (`ClusterStorage`) at a
///         deterministic, hardcoded slot. Append-only field additions are upgrade-safe;
///         no slot collisions with parent contracts (which are also ERC-7201) and no
///         brittle trailing __gap. Public auto-getters that the legacy linear layout
///         exposed are preserved as explicit view functions of identical signatures so
///         off-chain consumers' ABIs are unchanged.
contract TeeSqlClusterApp is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    PausableUpgradeable,
    IAppAuth,
    IAppAuthBasicManagement,
    IKmsRootRegistry
{
    // --- Public types (referenced in function signatures + by derived/test contracts) ---

    struct Member {
        address instanceId;
        bytes derivedPubkey;
        address derivedAddr;
        address passthrough;
        bytes endpoint; // AES-GCM ct of tailnet IP; peer-to-peer only.
        uint256 registeredAt;
        bytes publicEndpoint; // UTF-8 public URL (Phala gateway or operator host).
        string dnsLabel; // Per-member DNS UUID; sidecar-derived from derivedPubkey, used to
        // publish `status.<dnsLabel>.teesql.com` CNAMEs via the dns-controller.
    }

    struct OnboardMsg {
        bytes32 fromMember;
        bytes encryptedPayload;
    }

    struct AuthorizedSigner {
        uint8 permissions;
        bool active;
        uint256 authorizedAt;
    }

    struct Witness {
        bytes32 voucherMemberId;
        bytes sig;
    }

    struct RegisterArgs {
        DstackSigChain.Proof sigChainProof;
        bytes bindingSig;
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

    // --- ERC-7201 namespaced storage ---
    //
    // Single struct at a deterministic, hardcoded slot. Append fields freely; they
    // grow at higher offsets within the struct without ever colliding with inherited
    // (also-namespaced) parent storage.
    //
    // Slot was computed once via:
    //   inner = keccak256("teesql.storage.ClusterApp")
    //         = 0xbb0a434d4b2d92527abbb6d719547b08d0c59b8ed306d426f6dbfa6695b777db
    //   slot  = keccak256(abi.encode(uint256(inner) - 1)) & ~bytes32(uint256(0xff))
    //         = 0x41483450a74c9b52ed8d4d09a3915b6b80e5239e1c6e8f2780ae20665a6daa00

    /// @custom:storage-location erc7201:teesql.storage.ClusterApp
    struct ClusterStorage {
        // Cluster identity
        string clusterId;
        // KMS boot gate
        mapping(bytes32 => bool) allowedComposeHashes;
        mapping(bytes32 => bool) allowedDeviceIds;
        bool allowAnyDevice;
        // Sig-chain trust anchors (covers IKmsRootRegistry)
        mapping(address => bool) allowedKmsRoots;
        // Membership
        mapping(bytes32 => Member) members;
        mapping(address => bytes32) instanceToMember;
        mapping(address => bytes32) derivedToMember;
        mapping(bytes32 => uint256) memberNonce;
        // Onboarding
        mapping(bytes32 => OnboardMsg[]) onboarding;
        // Signer authorization (cluster-scoped)
        mapping(address => AuthorizedSigner) authorizedSigners;
        // Leader lease (no TTL — replaced only by higher-epoch claimLeader)
        bytes32 leaderMemberId;
        uint256 leaderEpoch;
        // Passthrough registry
        mapping(address => bool) isOurPassthrough;
        address kms;
        uint256 nextMemberSeq;
        // Pause authority
        address pauser;
        // TCB-freshness policy. Mirrors the dstack DstackApp setting; surfaced
        // via `IAppAuthBasicManagement.requireTcbUpToDate()` for operator
        // tooling and consulted at boot in `isAppAllowed`: when true, a CVM
        // whose `AppBootInfo.tcbStatus` is anything other than `"UpToDate"`
        // is rejected. Default false, so existing clusters continue to admit
        // any TCB status until an operator explicitly opts in via
        // `setRequireTcbUpToDate(true)`.
        bool requireTcbUpToDate;
        // Cluster lifecycle. `destroyedAt != 0` is the irreversible
        // "this proxy is forever stranded" signal. Once set, every mutator
        // gated on `whenNotDestroyed` reverts; `isAppAllowed` returns
        // `(false, "cluster destroyed")` for any boot quote; public reads
        // stay live so forensic tooling can still walk the contract.
        uint256 destroyedAt;
        // Per-member lifecycle. `memberRetiredAt[id] != 0` removes the
        // member from elections and gates its `_verifyCall`-using
        // mutators (claimLeader / updateEndpoint / updatePublicEndpoint /
        // onboard). The Member record itself stays in storage so
        // historical queries continue to resolve.
        mapping(bytes32 => uint256) memberRetiredAt;
        // Direct passthrough -> memberId lookup. Populated alongside
        // `instanceToMember` and `derivedToMember` in `register()`. Lets
        // operator tooling (CLI `retire-member --passthrough …`) skip
        // the `MemberRegistered` event scan and resolve memberId in a
        // single SLOAD.
        mapping(address => bytes32) passthroughToMember;
    }

    bytes32 public constant STORAGE_LOCATION =
        0x41483450a74c9b52ed8d4d09a3915b6b80e5239e1c6e8f2780ae20665a6daa00;

    function _$() internal pure returns (ClusterStorage storage $) {
        bytes32 location = STORAGE_LOCATION;
        assembly {
            $.slot := location
        }
    }

    // --- Version markers ---
    //
    // Two independent counters live in this contract. Don't conflate them.
    //
    //   `version()` (below) — implementation identity, returned as a
    //   monotonically increasing `uint256`. Bump on every impl upgrade so
    //   operators can tell at a glance which logic the proxy is running.
    //   `1` is the first stable impl shipped under the ERC-7201 +
    //   Ownable2Step design; `2` adds the `destroy()` / `retireMember()`
    //   lifecycle surface plus `passthroughToMember` lookup.
    //
    //   `_REGISTER_MSG_PREFIX` / `_CALL_MSG_PREFIX` / `_WITNESS_MSG_PREFIX`
    //   below — *signed-message format* identifiers. Each is a non-replay
    //   tag baked into the keccak256 input the sidecar signs. Bump them
    //   ONLY when the message *fields or encoding* change (different
    //   args, different abi.encode order, etc.) — not on every impl
    //   upgrade. A contract `version()` bump that doesn't change message
    //   shapes leaves these alone.
    //
    //   When a format version bumps, the contract constant AND any
    //   sidecar/CLI Rust code that reproduces the prefix locally must
    //   change in lockstep — otherwise the sidecar's signature won't
    //   verify. Today the only Rust-side reproduction is
    //   `_CALL_MSG_PREFIX` in
    //   `open-source/teesql-sidecar/crates/sidecar/src/group_auth.rs`
    //   (the sidecar fetches the other two via on-chain `registrationMessage()`
    //   and `witnessMessage()` views, so changing those is contract-only).

    /// Registration-message tag. Bumped to `:v3` on 2026-04-29 to drop the
    /// `role` field and lock out v2 sidecars (see
    /// `docs/state/2026-04-30-runtime-role-status.md`). Computed entirely
    /// on-chain via `registrationMessage()`; sidecars do not reproduce this
    /// string locally.
    string private constant _REGISTER_MSG_PREFIX = "teesql-cluster-register:v3";

    /// Per-call-auth tag. Reproduced verbatim in sidecar
    /// `group_auth.rs`'s `call_auth_hash` for off-chain pre-computation —
    /// must change in lockstep on any format bump.
    string private constant _CALL_MSG_PREFIX = "teesql-cluster-call:v1";

    /// Witness (offline-leader-attestation) tag. Computed on-chain via
    /// `witnessMessage()`; sidecars do not reproduce this string locally.
    string private constant _WITNESS_MSG_PREFIX = "teesql-leader-offline:v1";

    /// @notice Implementation identity. Increments on every UUPS impl
    ///         upgrade (1, 2, 3, …). Operator-facing: the answer to
    ///         "which logic is this proxy running?" without
    ///         eth_getStorageAt'ing the EIP-1967 implementation slot.
    /// @dev    Distinct from the internal signed-message format markers
    ///         (`_REGISTER_MSG_PREFIX` etc.) which only bump when the
    ///         message *shape* changes. See the version-markers block above.
    function version() external pure override returns (uint256) {
        return 2;
    }

    // --- Events ---
    event MemberPassthroughCreated(address indexed passthrough, bytes32 indexed salt);
    event MemberRegistered(
        bytes32 indexed memberId, address indexed instanceId, address indexed passthrough, string dnsLabel
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
    event KmsSet(address indexed kms);
    event PauserSet(address indexed pauser);

    /// @notice Emitted exactly once when the cluster transitions to the
    ///         terminal `destroyed` state. Consumers (dns-controller,
    ///         monitoring-hub) watch this signal to converge their views
    ///         of the cluster to "gone forever" and stop reconciling
    ///         records that pointed at it.
    event ClusterDestroyed(uint256 timestamp);

    /// @notice Emitted exactly once per member when retired. Member rows
    ///         remain readable post-retire; the flag is what filters
    ///         them out of election candidacy and gates their per-call-
    ///         auth mutators.
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
    error ZeroAddress();
    error BadPerms();
    error NotAuthorized();
    /// @dev Trailing underscore avoids identifier collision with the
    ///      `ClusterDestroyed(uint256)` event on the same contract; a
    ///      bare `revert ClusterDestroyed()` would be ambiguous to the
    ///      compiler.
    error ClusterDestroyed_();
    /// @dev Same naming rule as `ClusterDestroyed_` — disambiguates from
    ///      the `MemberRetired(bytes32,uint256)` event.
    error MemberRetired_();
    error AlreadyRetired();
    error CannotRetireLeader();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice One-shot v1 initializer. Sets owner, pauser, kms, clusterId, and
    ///         seeds allowed KMS roots. Locked via OZ's `initializer` modifier —
    ///         can never be called twice.
    ///
    /// @dev    For future upgrades that need to populate newly-added fields in
    ///         `ClusterStorage`, use OZ's `reinitializer(N)` mechanism. There
    ///         are two equivalent conventions, both supported here:
    ///
    ///         (1) **Override the `reinitialize` virtual hook below.** v2+ keeps
    ///             a single entry point with a generic `(uint64 version, bytes
    ///             data)` signature, which makes upgrade-tooling consistent
    ///             across versions:
    ///
    ///                 function reinitialize(uint64 version, bytes calldata data)
    ///                     public override reinitializer(version)
    ///                 {
    ///                     require(version == 2, "wrong version");
    ///                     (address treasury) = abi.decode(data, (address));
    ///                     _$().treasury = treasury;
    ///                 }
    ///
    ///         (2) **Add a per-version sibling** like `reinitializeV2` (closer
    ///             to OZ's documented convention; one function per release):
    ///
    ///                 function reinitializeV2(address treasury) external reinitializer(2) {
    ///                     _$().treasury = treasury;
    ///                 }
    ///
    ///         Either way, run the upgrade atomically with the init call so the
    ///         new state can never be observed in an uninitialized middle state:
    ///
    ///             cluster.upgradeToAndCall(
    ///                 newImpl,
    ///                 abi.encodeCall(this.reinitializeV2, (treasury))
    ///             );
    ///
    ///         `reinitializer(N)` allows the call exactly once when the version
    ///         sentinel is `< N`, then bumps it to `N`. Versions are strictly
    ///         monotonic; never reuse a prior N.
    function initialize(
        address _owner,
        address _pauser_,
        address _kms,
        string calldata _clusterId,
        address[] calldata _kmsRoots
    ) external initializer {
        if (_owner == address(0) || _pauser_ == address(0) || _kms == address(0)) {
            revert ZeroAddress();
        }
        __Ownable_init(_owner);
        __Ownable2Step_init();
        __Pausable_init();

        ClusterStorage storage $ = _$();
        $.pauser = _pauser_;
        $.kms = _kms;
        $.clusterId = _clusterId;
        emit PauserSet(_pauser_);
        emit KmsSet(_kms);

        for (uint256 i = 0; i < _kmsRoots.length; i++) {
            if (_kmsRoots[i] == address(0)) revert ZeroAddress();
            $.allowedKmsRoots[_kmsRoots[i]] = true;
            emit KmsRootAdded(_kmsRoots[i]);
        }
    }

    /// @notice Convention placeholder for v2+ post-upgrade state migrations.
    ///         v1 has no fields to migrate, so this reverts to keep stale
    ///         operator scripts from accidentally consuming a version
    ///         sentinel. Future versions OVERRIDE this hook (or define a
    ///         per-version sibling like `reinitializeV2`) — see the doc-
    ///         comment on `initialize` above for the full pattern.
    /// @dev    Intentionally NOT marked with `reinitializer(N)` — the
    ///         override is responsible for choosing the version.
    function reinitialize(uint64, bytes calldata) public virtual {
        revert("TeeSqlClusterApp: no reinitializer for this version");
    }

    // --- Passthrough factory ---

    /// @notice CREATE2-deploy a new TeeSqlClusterMember passthrough and register it with DstackKms.
    /// @dev    Permissionless: deploying a passthrough is inert until a CVM boots under it and passes
    ///         `register()`. Compose/device/KMS-root allowlists gate any effective use.
    ///
    ///         **Impl-specific bytecode.** The deployed passthrough's bytecode is
    ///         `type(TeeSqlClusterMember).creationCode` baked in at THIS cluster
    ///         impl's compile time. A future cluster UUPS upgrade that also
    ///         modifies `TeeSqlClusterMember` will produce a different bytecode
    ///         hash → a different CREATE2 address space for the same salt. Already-
    ///         deployed members keep working at their original addresses; new
    ///         members deployed after the upgrade live in the new address space.
    ///         See `predictMember` for the operator-side implication.
    function createMember(bytes32 salt) external whenNotPaused returns (address passthrough) {
        ClusterStorage storage $ = _$();
        bytes32 effectiveSalt = salt == bytes32(0) ? bytes32(uint256($.nextMemberSeq++)) : salt;
        passthrough = address(new TeeSqlClusterMember{salt: effectiveSalt}(address(this)));
        IDstackKms($.kms).registerApp(passthrough);
        $.isOurPassthrough[passthrough] = true;
        emit MemberPassthroughCreated(passthrough, effectiveSalt);
    }

    /// @notice Predict a passthrough address for a given salt without deploying.
    /// @dev    The returned address is computed from `(0xff, cluster, salt,
    ///         keccak256(creationCode || abi.encode(cluster)))` per CREATE2 — and
    ///         `creationCode` is the CURRENT cluster impl's bytecode for
    ///         `TeeSqlClusterMember`. That means:
    ///
    ///         **Predictions are NOT stable across cluster impl upgrades that
    ///         change `TeeSqlClusterMember`.** A salt that resolves to address
    ///         `0xAAA…` under cluster impl v1 may resolve to `0xBBB…` under v2.
    ///         The cluster's `createMember` and `predictMember` use the same
    ///         `creationCode` reference within one impl, so they stay in sync —
    ///         but never persist a (salt → predicted address) pair across an
    ///         upgrade boundary.
    ///
    ///         **Operator rule:** always recompute the prediction immediately
    ///         before calling `createMember`. Don't cache it in config files,
    ///         deploy scripts, or runbooks longer than a single deploy attempt.
    function predictMember(bytes32 salt) external view returns (address) {
        bytes32 effectiveSalt = salt == bytes32(0) ? bytes32(uint256(_$().nextMemberSeq)) : salt;
        bytes32 bytecodeHash =
            keccak256(abi.encodePacked(type(TeeSqlClusterMember).creationCode, abi.encode(address(this))));
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), effectiveSalt, bytecodeHash))))
        );
    }

    // --- IAppAuth (called by passthrough, which is called by DstackKms) ---
    function isAppAllowed(AppBootInfo calldata b) external view override returns (bool, string memory) {
        ClusterStorage storage $ = _$();
        // Destroy gate runs first so the canonical "this proxy is
        // forever stranded" reason wins over pause / passthrough /
        // compose / device / TCB. Operators reading boot rejections
        // should never have to guess whether a destroyed cluster was
        // also paused or had a stale device id.
        if ($.destroyedAt != 0) return (false, "cluster destroyed");
        if (paused()) return (false, "cluster paused");
        if (!$.isOurPassthrough[b.appId]) return (false, "unknown passthrough");
        if (!$.allowedComposeHashes[b.composeHash]) return (false, "compose hash not allowed");
        if (!$.allowAnyDevice && !$.allowedDeviceIds[b.deviceId]) return (false, "device not allowed");
        // Optional TCB-freshness gate. dstack populates `tcbStatus` from the
        // KMS's policy decision over the boot quote; "UpToDate" is the
        // canonical Intel TDX value for a TCB matching the latest published
        // SVN. We compare bytes rather than recasting to a string-id enum so
        // a future Intel string addition doesn't silently reclassify CVMs.
        if ($.requireTcbUpToDate && keccak256(bytes(b.tcbStatus)) != keccak256(bytes("UpToDate"))) {
            return (false, "tcb not up to date");
        }
        return (true, "");
    }

    // --- Registration ---

    /// @notice Registration binding commits to every registered field so a gas relay cannot
    ///         rewrite endpoint/publicEndpoint/dnsLabel/instance_id. Pins to (chainId, clusterApp)
    ///         to prevent cross-contract / cross-chain replay.
    function registrationMessage(
        address instanceId,
        bytes calldata endpoint,
        bytes calldata publicEndpoint,
        string calldata dnsLabel
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                _REGISTER_MSG_PREFIX,
                block.chainid,
                address(this),
                _$().clusterId,
                instanceId,
                endpoint,
                publicEndpoint,
                dnsLabel
            )
        );
    }

    function register(RegisterArgs calldata a) external whenNotPaused whenNotDestroyed returns (bytes32 memberId) {
        ClusterStorage storage $ = _$();
        DstackSigChain.Proof memory proof = a.sigChainProof;
        (bytes32 codeId, bytes memory derivedPubkey) = DstackSigChain.verify(proof, this);
        // codeId is bytes32(bytes20(app_id)) — left-aligned. Take the leftmost 20 bytes.
        address passthrough = address(bytes20(codeId));
        if (!$.isOurPassthrough[passthrough]) revert WrongAppId();

        bytes32 bindHash = registrationMessage(a.instanceId, a.endpoint, a.publicEndpoint, a.dnsLabel);
        bytes32 bindEthHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", bindHash));
        address derivedAddr = DstackSigChain.compressedToAddress(derivedPubkey);
        address recovered = DstackSigChain.recover(bindEthHash, a.bindingSig);
        if (recovered != derivedAddr) revert InstanceBindingInvalid();

        memberId = keccak256(derivedPubkey);
        $.members[memberId] = Member({
            instanceId: a.instanceId,
            derivedPubkey: derivedPubkey,
            derivedAddr: derivedAddr,
            passthrough: passthrough,
            endpoint: a.endpoint,
            registeredAt: block.timestamp,
            publicEndpoint: a.publicEndpoint,
            dnsLabel: a.dnsLabel
        });
        $.instanceToMember[a.instanceId] = memberId;
        $.derivedToMember[derivedAddr] = memberId;
        // Direct passthrough -> memberId. CLI's retire-member flow
        // resolves memberId from the operator-supplied passthrough via
        // a single SLOAD instead of a multi-block MemberRegistered
        // event scan. Future boot-gate work that wants a per-member
        // retired check inside `isAppAllowed` would also rely on this.
        $.passthroughToMember[passthrough] = memberId;
        emit MemberRegistered(memberId, a.instanceId, passthrough, a.dnsLabel);
        emit InstanceBindingVerified(memberId, a.instanceId);
    }

    // --- Per-call auth ---

    function callMessage(bytes32 memberId, uint256 nonce, bytes4 selector, bytes memory args)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                _CALL_MSG_PREFIX, block.chainid, address(this), memberId, nonce, selector, keccak256(args)
            )
        );
    }

    function _verifyCall(CallAuth calldata a, bytes4 selector, bytes memory args) internal returns (bytes32) {
        ClusterStorage storage $ = _$();
        Member storage m = $.members[a.memberId];
        if (m.registeredAt == 0) revert NotMember();
        // Retired members can no longer drive any per-call-auth mutator
        // (claimLeader / updateEndpoint / updatePublicEndpoint / onboard).
        // Boot-time `isAppAllowed` does NOT consult this — a retired CVM
        // is presumed gone, and if it isn't, every state-changing path
        // it can drive reverts here.
        if ($.memberRetiredAt[a.memberId] != 0) revert MemberRetired_();
        if (a.nonce != $.memberNonce[a.memberId]) revert BadNonce();

        bytes32 h = callMessage(a.memberId, a.nonce, selector, args);
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        address signer = DstackSigChain.recover(ethHash, a.sig);
        if (signer != m.derivedAddr) revert BadSig();

        unchecked {
            $.memberNonce[a.memberId] = a.nonce + 1;
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
                _WITNESS_MSG_PREFIX,
                block.chainid,
                address(this),
                _$().clusterId,
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
        whenNotDestroyed
    {
        bytes32 memberId = _verifyCall(auth, this.claimLeader.selector, abi.encode(newEndpoint, witnesses));
        ClusterStorage storage $ = _$();

        bytes32 currentLeaderId = $.leaderMemberId;
        uint256 currentEpoch = $.leaderEpoch;

        if (currentLeaderId != bytes32(0) && currentLeaderId != memberId) {
            if (witnesses.length == 0) revert NoWitness();
            bytes32[] memory seen = new bytes32[](witnesses.length);
            for (uint256 i = 0; i < witnesses.length; i++) {
                bytes32 vId = witnesses[i].voucherMemberId;
                if (vId == memberId) revert SelfWitness();
                if ($.members[vId].registeredAt == 0) revert WitnessNotMember();
                for (uint256 j = 0; j < i; j++) {
                    if (seen[j] == vId) revert DuplicateWitness();
                }
                seen[i] = vId;

                bytes32 wMsg = witnessMessage(currentLeaderId, currentEpoch, vId);
                bytes32 wEthHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", wMsg));
                address recovered = DstackSigChain.recover(wEthHash, witnesses[i].sig);
                if (recovered != $.members[vId].derivedAddr) revert BadWitnessSig();
            }
        }

        uint256 newEpoch = currentEpoch + 1;
        $.leaderMemberId = memberId;
        $.leaderEpoch = newEpoch;
        $.members[memberId].endpoint = newEndpoint;
        emit LeaderClaimed(memberId, newEpoch, newEndpoint);
    }

    /// @notice Update this member's encrypted tailnet endpoint without bumping the leader epoch.
    ///         Called by secondaries post-onboarding (once they have the cluster key) and on
    ///         tailnet-IP changes.
    function updateEndpoint(CallAuth calldata auth, bytes calldata newEndpoint) external whenNotPaused whenNotDestroyed {
        bytes32 memberId = _verifyCall(auth, this.updateEndpoint.selector, abi.encode(newEndpoint));
        _$().members[memberId].endpoint = newEndpoint;
        emit EndpointUpdated(memberId, newEndpoint);
    }

    /// @notice Update this member's customer-facing public URL.
    function updatePublicEndpoint(CallAuth calldata auth, bytes calldata newPublicEndpoint)
        external
        whenNotPaused
        whenNotDestroyed
    {
        bytes32 memberId = _verifyCall(auth, this.updatePublicEndpoint.selector, abi.encode(newPublicEndpoint));
        _$().members[memberId].publicEndpoint = newPublicEndpoint;
        emit PublicEndpointUpdated(memberId, newPublicEndpoint);
    }

    function currentLeader() external view returns (Member memory) {
        ClusterStorage storage $ = _$();
        if ($.leaderMemberId == bytes32(0)) revert NotLeaderClaimant();
        return $.members[$.leaderMemberId];
    }

    /// @notice ABI-compatible view that mirrors the historical leaderLease auto-getter shape.
    function leaderLease() external view returns (bytes32 memberId, uint256 epoch) {
        ClusterStorage storage $ = _$();
        return ($.leaderMemberId, $.leaderEpoch);
    }

    // --- Onboarding ---

    function onboard(CallAuth calldata auth, bytes32 toId, bytes calldata payload)
        external
        whenNotPaused
        whenNotDestroyed
    {
        bytes32 fromId = _verifyCall(auth, this.onboard.selector, abi.encode(toId, payload));
        ClusterStorage storage $ = _$();
        if ($.members[toId].registeredAt == 0) revert NotMember();
        $.onboarding[toId].push(OnboardMsg({fromMember: fromId, encryptedPayload: payload}));
        emit OnboardingPosted(toId, fromId);
    }

    // --- Admin ---
    //
    // The four `IAppAuthBasicManagement` mutators accept calls from EITHER:
    //   * the cluster owner (canonical), OR
    //   * one of our own registered passthroughs (`_$().isOurPassthrough[caller]`).
    //
    // The passthrough path exists so phala-cli's in-place CVM-update flow
    // (`phala deploy --cvm-id`) can target the CVM's `app_id` (a passthrough)
    // and have its `addComposeHash` / `addDevice` forward through to the
    // cluster's allowlist. The trust model stays sound: passthroughs are minted
    // exclusively by `createMember`, the member contract's own gate (see
    // `TeeSqlClusterMember.addComposeHash`) requires `msg.sender == cluster.owner()`
    // before forwarding, and the registered-passthrough check below confirms
    // `msg.sender` is one of ours rather than an arbitrary contract impersonating
    // a passthrough address.

    function _onlyOwnerOrPassthrough() internal view {
        if (msg.sender != owner() && !_$().isOurPassthrough[msg.sender]) {
            revert NotAuthorized();
        }
    }

    function addComposeHash(bytes32 h) external override whenNotDestroyed {
        _onlyOwnerOrPassthrough();
        _$().allowedComposeHashes[h] = true;
        emit ComposeHashAdded(h);
    }

    function removeComposeHash(bytes32 h) external override whenNotDestroyed {
        _onlyOwnerOrPassthrough();
        _$().allowedComposeHashes[h] = false;
        emit ComposeHashRemoved(h);
    }

    function addDevice(bytes32 d) external override whenNotDestroyed {
        _onlyOwnerOrPassthrough();
        _$().allowedDeviceIds[d] = true;
        emit DeviceAdded(d);
    }

    function removeDevice(bytes32 d) external override whenNotDestroyed {
        _onlyOwnerOrPassthrough();
        _$().allowedDeviceIds[d] = false;
        emit DeviceRemoved(d);
    }

    function setAllowAnyDevice(bool v) external override whenNotDestroyed {
        _onlyOwnerOrPassthrough();
        _$().allowAnyDevice = v;
        emit AllowAnyDeviceSet(v);
    }

    function setRequireTcbUpToDate(bool v) external override whenNotDestroyed {
        _onlyOwnerOrPassthrough();
        _$().requireTcbUpToDate = v;
        emit RequireTcbUpToDateSet(v);
    }

    function addKmsRoot(address r) external onlyOwner whenNotDestroyed {
        if (r == address(0)) revert ZeroAddress();
        _$().allowedKmsRoots[r] = true;
        emit KmsRootAdded(r);
    }

    function removeKmsRoot(address r) external onlyOwner whenNotDestroyed {
        _$().allowedKmsRoots[r] = false;
        emit KmsRootRemoved(r);
    }

    function authorizeSigner(address s, uint8 p) external onlyOwner whenNotDestroyed {
        if (s == address(0)) revert ZeroAddress();
        if (p == 0 || p > 3) revert BadPerms();
        _$().authorizedSigners[s] = AuthorizedSigner(p, true, block.timestamp);
        emit SignerAuthorized(s, p);
    }

    function revokeSigner(address s) external onlyOwner whenNotDestroyed {
        _$().authorizedSigners[s].active = false;
        emit SignerRevoked(s);
    }

    function setKms(address k) external onlyOwner whenNotDestroyed {
        if (k == address(0)) revert ZeroAddress();
        _$().kms = k;
        emit KmsSet(k);
    }

    // --- Lifecycle modifier ---
    /// @dev Reverts every gated mutator once `destroyedAt` is set.
    ///      Owner housekeeping (`transferOwnership`, `acceptOwnership`,
    ///      `unpause`) is intentionally NOT gated — destruction shouldn't
    ///      lock the owner out of forensic admin. `pause`/`unpause` stay
    ///      transient and are unaffected; `setPauser` is gated so a new
    ///      pauser can't be installed on a stranded contract.
    modifier whenNotDestroyed() {
        if (_$().destroyedAt != 0) revert ClusterDestroyed_();
        _;
    }

    // --- Pause ---
    modifier onlyPauser() {
        if (msg.sender != _$().pauser) revert NotAuthorized();
        _;
    }

    function pause() external onlyPauser {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function pauser() external view returns (address) {
        return _$().pauser;
    }

    function setPauser(address p) external onlyOwner whenNotDestroyed {
        if (p == address(0)) revert ZeroAddress();
        _$().pauser = p;
        emit PauserSet(p);
    }

    // --- Lifecycle: destroy + retire ---

    /// @notice Mark the cluster as permanently destroyed. Disables boot
    ///         via `isAppAllowed`, reverts every gated mutator, leaves
    ///         all reads live for forensics. One-way: there is no
    ///         counterpart `undestroy()` and never will be — recovery
    ///         means a fresh proxy.
    /// @dev    Owner-only. Idempotent revert (`ClusterDestroyed_`) on
    ///         second call. Emits `ClusterDestroyed(timestamp)` exactly
    ///         once. `pause`/`unpause` and ownership transfer remain
    ///         callable so the operator isn't locked out of housekeeping.
    function destroy() external onlyOwner whenNotDestroyed {
        ClusterStorage storage $ = _$();
        $.destroyedAt = block.timestamp;
        emit ClusterDestroyed(block.timestamp);
    }

    /// @notice Mark a member as permanently retired. Filters them out
    ///         of backup-taker / auto-promote candidacy on the sidecar
    ///         side and reverts every per-call-auth mutator they could
    ///         drive. Reads (`getMember`, etc.) remain live so historical
    ///         queries continue to resolve.
    /// @dev    Owner-only and irreversible. The current leader cannot
    ///         be retired in place — the operator must rotate to a new
    ///         leader via `claimLeader` first. This preserves the
    ///         witness-flow's ordering guarantees: the cluster is never
    ///         observably leader-less in the same tx that retired the
    ///         leader.
    function retireMember(bytes32 memberId) external onlyOwner whenNotDestroyed {
        ClusterStorage storage $ = _$();
        if ($.members[memberId].registeredAt == 0) revert NotMember();
        if ($.memberRetiredAt[memberId] != 0) revert AlreadyRetired();
        if (memberId == $.leaderMemberId) revert CannotRetireLeader();
        $.memberRetiredAt[memberId] = block.timestamp;
        emit MemberRetired(memberId, block.timestamp);
    }

    // --- Views: explicit getters preserving prior auto-getter ABIs ---

    function clusterId() external view returns (string memory) {
        return _$().clusterId;
    }

    function allowedComposeHashes(bytes32 h) external view override returns (bool) {
        return _$().allowedComposeHashes[h];
    }

    function allowedDeviceIds(bytes32 d) external view override returns (bool) {
        return _$().allowedDeviceIds[d];
    }

    function allowAnyDevice() external view override returns (bool) {
        return _$().allowAnyDevice;
    }

    function requireTcbUpToDate() external view override returns (bool) {
        return _$().requireTcbUpToDate;
    }

    /// @dev Disambiguates between `OwnableUpgradeable.owner()` and
    ///      `IAppAuthBasicManagement.owner()` after the interface expansion
    ///      added the read-side mirror. Same semantics as `OwnableUpgradeable`.
    function owner()
        public
        view
        virtual
        override(OwnableUpgradeable, IAppAuthBasicManagement)
        returns (address)
    {
        return super.owner();
    }

    function allowedKmsRoots(address r) external view override returns (bool) {
        return _$().allowedKmsRoots[r];
    }

    function instanceToMember(address i) external view returns (bytes32) {
        return _$().instanceToMember[i];
    }

    function derivedToMember(address d) external view returns (bytes32) {
        return _$().derivedToMember[d];
    }

    function memberNonce(bytes32 m) external view returns (uint256) {
        return _$().memberNonce[m];
    }

    function authorizedSigners(address s) external view returns (uint8 permissions, bool active, uint256 authorizedAt) {
        AuthorizedSigner storage a = _$().authorizedSigners[s];
        return (a.permissions, a.active, a.authorizedAt);
    }

    function isOurPassthrough(address p) external view returns (bool) {
        return _$().isOurPassthrough[p];
    }

    function kms() external view returns (address) {
        return _$().kms;
    }

    function nextMemberSeq() external view returns (uint256) {
        return _$().nextMemberSeq;
    }

    function isSignerAuthorized(address s, uint8 required) external view returns (bool) {
        AuthorizedSigner storage a = _$().authorizedSigners[s];
        return a.active && (a.permissions & required) == required;
    }

    function getMember(bytes32 id) external view returns (Member memory) {
        return _$().members[id];
    }

    /// @notice Block timestamp at which the cluster was destroyed; 0 if
    ///         the cluster is still active.
    function destroyedAt() external view returns (uint256) {
        return _$().destroyedAt;
    }

    /// @notice Convenience boolean view; equivalent to `destroyedAt() != 0`.
    function destroyed() external view returns (bool) {
        return _$().destroyedAt != 0;
    }

    /// @notice Block timestamp at which `memberId` was retired; 0 if
    ///         still active. Member rows themselves remain readable
    ///         post-retire — this flag is the only state change.
    function memberRetiredAt(bytes32 memberId) external view returns (uint256) {
        return _$().memberRetiredAt[memberId];
    }

    /// @notice Direct passthrough -> memberId lookup. Returns
    ///         `bytes32(0)` for an unregistered passthrough. Callers
    ///         should treat zero as "no such member" rather than
    ///         dispatch on it.
    function passthroughToMember(address p) external view returns (bytes32) {
        return _$().passthroughToMember[p];
    }

    function getOnboarding(bytes32 id) external view returns (OnboardMsg[] memory) {
        return _$().onboarding[id];
    }

    function supportsInterface(bytes4 id) public view virtual override returns (bool) {
        return id == type(IAppAuth).interfaceId || id == type(IAppAuthBasicManagement).interfaceId
            || id == type(IERC165).interfaceId;
    }

    // --- UUPS ---
    function _authorizeUpgrade(address) internal override onlyOwner {}
}

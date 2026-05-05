// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {OwnableStorage} from "@solidstate/contracts/access/ownable/OwnableStorage.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import {ControlPlaneStorage} from "../storage/ControlPlaneStorage.sol";
import {CoreStorage} from "../storage/CoreStorage.sol";
import {LifecycleStorage} from "../storage/LifecycleStorage.sol";
import {BitmapNonces} from "../libraries/BitmapNonces.sol";
import {ControlPlaneEnvelope} from "../libraries/ControlPlaneEnvelope.sol";
import {DstackSigChain} from "../DstackSigChain.sol";

/// @title ControlPlaneFacet
/// @notice Broadcast-only on-chain control surface for the cluster Diamond
///         (spec `docs/specs/control-plane-redesign.md` §5). Cluster-owner
///         Safe signs an EIP-712 envelope; the facet validates, marks the
///         nonce used in a 256-wide bitmap window, and emits an event the
///         chain-indexer fans out to member CVMs.
/// @dev    The facet itself is stateless governance plumbing — it does NOT
///         dispatch to other facets, mutate cluster state, or know the
///         instruction taxonomy. Instructions live encrypted inside
///         `env.ciphertext` and are interpreted by the control sidecar.
///
///         Authority. The signer is the Diamond's cluster-owner Safe, read
///         off `OwnableStorage.layout().owner` (the same slot AdminFacet's
///         `_ownerAddr()` and SolidStateDiamond's pre-registered SafeOwnable
///         surface read). Pre-Safe-handoff this is a deployer EOA, in which
///         case `isValidSignature` is invoked on the EOA which will revert
///         (EOAs don't implement EIP-1271) — the facet rejects with
///         `BadOwnerSig()`. The expected migration sequence is §10.2: the
///         Safe handoff lands BEFORE the first `submitControl` call.
///
///         clusterId bridging. The envelope's `bytes32 clusterId` is
///         compared against `keccak256(bytes(coreClusterId))` so the
///         existing `string` clusterId in CoreStorage continues to be the
///         operator-facing identifier; the on-chain bridge is just a hash.
///         This is the only sensible match: collision-resistant and
///         independent of arbitrary-length string padding ambiguities.
///
///         Receipt signature scheme. `submitReceipt` verifies a TEE-derived
///         secp256k1 signature against the member's `derivedAddr` from
///         `CoreStorage.members[memberId]`. The signed message is fixed in
///         `_receiptDigest` — it includes the chain id, diamond address,
///         clusterId-hash, instructionId, jobId, status, seq, logPointer,
///         and `keccak256(summary)` so a signature on one (member,
///         instruction, job, seq) tuple can not be replayed at any other
///         tuple, on any other cluster, on any other chain.
contract ControlPlaneFacet {
    using ControlPlaneEnvelope for ControlPlaneEnvelope.ControlEnvelope;
    using BitmapNonces for BitmapNonces.Layout;

    /// @dev EIP-1271 magic value. Returned by stock Safe Global v1.4.1 +
    ///      CompatibilityFallbackHandler when a presented signature
    ///      satisfies the Safe's threshold. Any other return value
    ///      (including a revert during the staticcall) means the
    ///      signature was rejected.
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /// @dev Receipt-message domain prefix. Matches the spec §5.8 receipt
    ///      construction string verbatim — off-chain signers (member
    ///      sidecars) MUST use this exact prefix. Bumping the version
    ///      ("v1" → "v2") is a fork; old + new signatures are mutually
    ///      inadmissible.
    string internal constant RECEIPT_MSG_PREFIX = "teesql-control-receipt:v1";

    // --- Errors ---

    /// @notice Envelope's clusterId hash does not match this Diamond's
    ///         clusterId hash.
    error WrongCluster();
    /// @notice Envelope's chainId field does not match `block.chainid`.
    error WrongChain();
    /// @notice Envelope's expiry has passed (`expiry <= block.timestamp`).
    error EnvelopeExpired();
    /// @notice The cluster-owner Safe's `isValidSignature` did not return
    ///         the EIP-1271 magic value (or the staticcall reverted).
    error BadOwnerSig();
    /// @notice The cluster has been destroyed — control plane is sealed.
    error ClusterDestroyed_();
    /// @notice msg.sender for `submitReceipt` is not a current member.
    error NotCurrentMember();
    /// @notice Member-derived signature recovery did not yield the member's
    ///         `derivedAddr`.
    error BadMemberSig();
    /// @notice `(memberId, instructionId)` already produced a receipt — the
    ///         per-job seen-set rejects re-emission so the indexer never
    ///         double-applies a side-effecting ack.
    error ReceiptAlreadySeen();
    /// @notice `seq` parameter on `submitReceipt` was zero. Receipt sequences
    ///         are 1-indexed (spec §8.1).
    error BadReceiptSeq();

    // --- Events ---

    /// @notice Emitted on every accepted control-instruction broadcast.
    ///         The chain-indexer subscribes to this event and fans out
    ///         per-cluster ordered streams to subscribing members.
    /// @dev    `ciphertextHash` and `ciphertext` are both included: the
    ///         hash so off-chain consumers can verify integrity without
    ///         re-hashing the event payload, the raw bytes so members
    ///         can decrypt without an extra round-trip to a state store.
    ///         The three indexed fields (`instructionId`, `clusterId`,
    ///         `nonce`) match the spec §5.3 shape.
    event ControlInstructionBroadcast(
        bytes32 indexed instructionId,
        bytes32 indexed clusterId,
        uint64 indexed nonce,
        bytes32[] targetMembers,
        uint64 expiry,
        bytes32 salt,
        bytes32 ciphertextHash,
        bytes ciphertext
    );

    /// @notice Per-member acknowledgement of a control instruction.
    ///         Status taxonomy is fixed at the contract surface so
    ///         off-chain decoders never need a separate enum sync:
    ///         1 = ACCEPTED, 2 = IN_PROGRESS, 3 = COMPLETED,
    ///         4 = FAILED, 5 = SUPERSEDED, 6 = EXPIRED.
    /// @dev    Three indexed fields per spec §5.3. `summary` is bytes
    ///         (rather than string) because the indexer treats it as
    ///         opaque encrypted payload — strings imply UTF-8 here.
    event ControlAck(
        bytes32 indexed instructionId,
        bytes32 indexed jobId,
        bytes32 indexed memberId,
        uint8 status,
        uint64 seq,
        bytes32 logPointer,
        bytes summary
    );

    /// @dev Reverts if the cluster has been irrevocably destroyed.
    ///      Mirrors CoreFacet's `whenNotDestroyed` so the control plane
    ///      cannot be used to drive a stranded diamond. We deliberately
    ///      do NOT honour the cluster-wide pause flag — control-plane
    ///      messages are explicit owner-signed requests and the pause
    ///      flag is itself a control-plane concern (a `pause` instruction
    ///      goes via this same envelope path).
    modifier whenNotDestroyed() {
        if (LifecycleStorage.layout().destroyedAt != 0) revert ClusterDestroyed_();
        _;
    }

    // ─── submitControl ────────────────────────────────────────────────

    /// @notice Submit a cluster-owner-signed control envelope. Validates
    ///         per spec §5.5; on success, marks the nonce used and emits
    ///         `ControlInstructionBroadcast`.
    /// @param env  The instruction envelope. `env.clusterId` is the keccak
    ///             of this Diamond's `string` clusterId; `env.chainId`
    ///             must equal `block.chainid`; `env.expiry` is a Unix
    ///             timestamp; `env.ciphertext` is opaque to the chain.
    /// @param sig  EIP-1271 signature from the cluster-owner Safe. For
    ///             stock Safe Global v1.4.1 this is the standard `Safe`
    ///             signature blob (potentially nested for multi-deep
    ///             contract-signature wrap; see spec §3.3).
    function submitControl(ControlPlaneEnvelope.ControlEnvelope calldata env, bytes calldata sig)
        external
        whenNotDestroyed
    {
        // 1. Cluster identity. The Diamond holds clusterId as a string;
        //    the envelope holds it as a bytes32. Bridge via keccak256 —
        //    collision-resistant and independent of string-length padding.
        bytes32 expectedCluster = keccak256(bytes(CoreStorage.layout().clusterId));
        if (env.clusterId != expectedCluster) revert WrongCluster();

        // 2. Chain pinning (in addition to the EIP-712 domain's
        //    block.chainid pin — belt-and-suspenders matches spec §5.5).
        if (env.chainId != block.chainid) revert WrongChain();

        // 3. Expiry. Strict inequality so an envelope timed at exactly
        //    block.timestamp is rejected.
        if (env.expiry <= block.timestamp) revert EnvelopeExpired();

        // 4. EIP-712 digest, pinned to this Diamond + chain via the
        //    domain separator inside `ControlPlaneEnvelope.digest`.
        bytes32 digestHash = ControlPlaneEnvelope.digest(env, address(this));

        // 5. EIP-1271 verification against the cluster-owner Safe. The
        //    canonical owner is OwnableStorage.layout().owner (set by
        //    DiamondInit + SafeOwnable). We use a low-level staticcall
        //    so a revert (e.g. owner is an EOA pre-handoff) is caught
        //    cleanly rather than bubbling up.
        address ownerSafe = OwnableStorage.layout().owner;
        (bool ok, bytes memory ret) =
            ownerSafe.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, digestHash, sig));
        // A revert (ok == false), a short return, or a wrong magic
        // value all collapse to BadOwnerSig — owner-signed-or-bust.
        if (!ok || ret.length < 32) revert BadOwnerSig();
        bytes4 magic = abi.decode(ret, (bytes4));
        if (magic != ERC1271_MAGIC_VALUE) revert BadOwnerSig();

        // 6. Mark the nonce used. BitmapNonces enforces both replay
        //    rejection (NonceAlreadyUsed) and below-window rejection
        //    (NonceOutOfWindow); both bubble up unchanged.
        ControlPlaneStorage.Layout storage cp = ControlPlaneStorage.layout();
        cp.nonces.markUsed(env.nonce);
        // Track the high-water mark separately for cheap monitoring
        // reads. This duplicates BitmapNonces' lastNonce — see
        // ControlPlaneStorage docstring for the rationale.
        if (env.nonce > cp.highestNonceSeen) {
            cp.highestNonceSeen = env.nonce;
        }

        // 7. Emit the broadcast event with the same fields the digest
        //    bound. Off-chain verifiers can recompute the digest from
        //    these fields + the sig and the owner Safe address.
        emit ControlInstructionBroadcast(
            env.instructionId,
            env.clusterId,
            env.nonce,
            env.targetMembers,
            env.expiry,
            env.salt,
            keccak256(env.ciphertext),
            env.ciphertext
        );
    }

    // ─── submitReceipt ────────────────────────────────────────────────

    /// @notice Submit a per-member acknowledgement of a control
    ///         instruction. Validates msg.sender is a registered current
    ///         member, the receipt signature recovers to the member's
    ///         derivedAddr, and the (memberId, instructionId) pair has
    ///         not already been seen.
    /// @param  instructionId  The originating envelope's `instructionId`.
    /// @param  jobId          Per-spec §8.2: keccak256(instructionId ||
    ///                        memberId || incarnation_nonce). Computed
    ///                        off-chain — the facet treats it as opaque.
    /// @param  status         1 = ACCEPTED, 2 = IN_PROGRESS, 3 = COMPLETED,
    ///                        4 = FAILED, 5 = SUPERSEDED, 6 = EXPIRED.
    /// @param  seq            Monotonic per (memberId, jobId), 1-indexed.
    /// @param  logPointer     keccak256 of the encrypted log payload that
    ///                        lives in R2 — `bytes32(0)` for non-terminal
    ///                        statuses.
    /// @param  summary        Opaque (encrypted) human-readable summary.
    /// @param  memberSig      65-byte secp256k1 ECDSA over EIP-191 of the
    ///                        receipt digest. Recovered against
    ///                        `members[memberId].derivedAddr`.
    /// @dev    Members are looked up by `derivedToMember[msg.sender]`,
    ///         which means a member's TEE-derived EOA is the on-chain
    ///         sender of its receipts. This is the same address its
    ///         signature recovers to — `msg.sender` and the recovered
    ///         signer must be equal. Anyone can relay the signed receipt
    ///         on chain so long as it is a registered member's, but in
    ///         the happy path the member submits its own receipt from
    ///         its TEE-derived EOA.
    function submitReceipt(
        bytes32 instructionId,
        bytes32 jobId,
        uint8 status,
        uint64 seq,
        bytes32 logPointer,
        bytes calldata summary,
        bytes calldata memberSig
    ) external whenNotDestroyed {
        if (seq == 0) revert BadReceiptSeq();

        // 1. msg.sender must be a current member. The derivedAddr index
        //    in CoreStorage is keyed by the TEE-derived EOA — exactly
        //    what the member signs the receipt with. Per spec §5.8 the
        //    receipt's recovered signer must match this same derivedAddr,
        //    which the explicit recovery below enforces independently of
        //    the msg.sender lookup.
        CoreStorage.Layout storage cs = CoreStorage.layout();
        bytes32 memberId = cs.derivedToMember[msg.sender];
        if (memberId == bytes32(0)) revert NotCurrentMember();
        CoreStorage.Member storage m = cs.members[memberId];
        if (m.registeredAt == 0) revert NotCurrentMember();
        if (LifecycleStorage.layout().memberRetiredAt[memberId] != 0) revert NotCurrentMember();

        // 2. Verify the TEE-derived signature. Construct the canonical
        //    receipt digest (spec §5.8) and recover the EIP-191-prefixed
        //    signer; compare against the member's derivedAddr.
        bytes32 receiptHash =
            _receiptDigest(cs.clusterId, instructionId, jobId, status, seq, logPointer, keccak256(summary));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", receiptHash));
        address recovered = DstackSigChain.recover(ethHash, memberSig);
        if (recovered != m.derivedAddr) revert BadMemberSig();

        // 3. Replay rejection. The seen-set is keyed on (memberId,
        //    instructionId): each member emits at most one acknowledgement
        //    per instruction (the receipt may carry the latest terminal
        //    status — but only one chain transaction per pair lands).
        //    Off-chain hubs that want a per-(memberId, jobId, seq)
        //    ordering reconstruct it from the event log; on chain we
        //    just need to defeat duplicate emission.
        ControlPlaneStorage.Layout storage cp = ControlPlaneStorage.layout();
        if (cp.memberJobsSeen[memberId][instructionId]) revert ReceiptAlreadySeen();
        cp.memberJobsSeen[memberId][instructionId] = true;
        unchecked {
            cp.receiptCount += 1;
        }

        emit ControlAck(instructionId, jobId, memberId, status, seq, logPointer, summary);
    }

    // ─── Read entrypoints ─────────────────────────────────────────────

    /// @notice Has the given envelope nonce ever been accepted by
    ///         `submitControl`? Note this returns true even for nonces
    ///         that have since fallen below the bitmap window — the
    ///         facet does not zero historical bits when the window
    ///         slides. Off-chain consumers that care about "could this
    ///         nonce still be submitted" must additionally check
    ///         `nonce > highestNonceSeen() - 256`.
    function isNonceUsed(uint64 nonce) external view returns (bool) {
        return BitmapNonces.isUsed(ControlPlaneStorage.layout().nonces, nonce);
    }

    /// @notice Has the given (memberId, instructionId) pair already
    ///         produced a receipt? True after the corresponding
    ///         `submitReceipt` lands, false otherwise.
    function isJobSeen(bytes32 memberId, bytes32 instructionId) external view returns (bool) {
        return ControlPlaneStorage.layout().memberJobsSeen[memberId][instructionId];
    }

    /// @notice Highest envelope nonce ever observed by `submitControl`.
    ///         The chain-indexer's cold-start logic uses this to seed
    ///         `next_expected_nonce` (spec §7.3).
    function highestNonceSeen() external view returns (uint64) {
        return ControlPlaneStorage.layout().highestNonceSeen;
    }

    /// @notice Total number of `submitReceipt` calls that have landed.
    ///         Cheap progress probe; not bound to any particular
    ///         instruction.
    function receiptCount() external view returns (uint64) {
        return ControlPlaneStorage.layout().receiptCount;
    }

    // ─── Helpers (public for off-chain digest reconstruction) ─────────

    /// @notice Compute the receipt digest the member's TEE-derived key
    ///         must sign. Exposed publicly so off-chain tooling (the
    ///         control sidecar) can rebuild it without reimplementing
    ///         the layout. The result is *unprefixed* — callers that
    ///         compose with EIP-191 must prepend `\x19Ethereum Signed
    ///         Message:\n32` themselves.
    /// @dev    Field ordering matches spec §5.8 verbatim. `clusterIdRaw`
    ///         is the underlying string clusterId; we keccak it inside
    ///         to match the bytes32 representation used by the envelope.
    function receiptMessage(
        bytes32 instructionId,
        bytes32 jobId,
        uint8 status,
        uint64 seq,
        bytes32 logPointer,
        bytes calldata summary
    ) external view returns (bytes32) {
        return _receiptDigest(
            CoreStorage.layout().clusterId, instructionId, jobId, status, seq, logPointer, keccak256(summary)
        );
    }

    /// @dev Receipt-digest construction. Matches spec §5.8 verbatim.
    ///      `clusterIdRaw` is the storage `string`; we hash it inside
    ///      so the on-chain digest is bytes32-only and matches what an
    ///      off-chain signer can build given just the bytes32-canonical
    ///      cluster id.
    function _receiptDigest(
        string memory clusterIdRaw,
        bytes32 instructionId,
        bytes32 jobId,
        uint8 status,
        uint64 seq,
        bytes32 logPointer,
        bytes32 summaryHash
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                RECEIPT_MSG_PREFIX,
                block.chainid,
                address(this),
                keccak256(bytes(clusterIdRaw)),
                instructionId,
                jobId,
                status,
                seq,
                logPointer,
                summaryHash
            )
        );
    }
}

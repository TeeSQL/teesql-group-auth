// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ControlPlaneEnvelope
/// @notice Pure library that builds the EIP-712 digest a ClusterOwnerSafe
///         signs to authorise a control-plane instruction broadcast. Lives
///         standalone so the ControlPlane facet (Track A1 of the rollout)
///         can compose it without inheritance or constructor wiring.
/// @dev    Spec: `docs/specs/control-plane-redesign.md` §5.4. The struct
///         shape and field ordering match §5.3 verbatim — both the
///         on-chain hash construction and the off-chain signer (hub UI
///         or `teesql cluster control submit` CLI) MUST agree on this
///         layout, so do not reorder fields without a coordinated
///         consumer-side bump.
///
///         Domain pinning. The domain has only `name`, `chainId`, and
///         `verifyingContract`. There is no `version` field — the
///         ControlPlane facet ships a single envelope schema and a v2
///         schema would be a fresh struct + fresh typehash, not a domain
///         version bump. Pinning to `address(this)` (passed in as
///         `verifyingContract`) means a signature for cluster A on
///         chain X is structurally inadmissible at cluster B, chain X
///         and at cluster A, chain Y.
///
///         `targetMembers` is encoded as `keccak256(abi.encodePacked(...))`
///         of the dynamic array — this is the EIP-712 standard
///         encoding for a `bytes32[]` typed-data field. An empty array
///         hashes to `keccak256("")` which is `0xc5d24601...` (the
///         empty-keccak constant) and is distinct from any non-empty
///         array, encoding the §5.6 broadcast-to-all semantic
///         unambiguously.
///
///         `ciphertext` is hashed (`keccak256`) before being folded into
///         the typed-data hash so the on-chain signature size is
///         independent of payload size. Off-chain consumers that want
///         to recompute the digest given an envelope MUST hash the
///         ciphertext bytes themselves; the wire-format event
///         `ControlInstructionBroadcast` carries `ciphertextHash`
///         alongside the raw `ciphertext` for exactly this purpose.
library ControlPlaneEnvelope {
    /// @notice EIP-712 typed-data envelope. Field order matches the
    ///         typehash string below — do not reorder.
    struct ControlEnvelope {
        bytes32 clusterId;
        bytes32[] targetMembers;
        bytes32 instructionId;
        uint64 nonce;
        uint256 chainId;
        uint64 expiry;
        bytes32 salt;
        bytes ciphertext;
    }

    /// @dev EIP-712 type strings. `TYPEHASH` covers the envelope; the
    ///      `bytes` field is rewritten as `bytes32 ciphertextHash` per
    ///      EIP-712's encoding rule for dynamic bytes.
    bytes32 internal constant TYPEHASH = keccak256(
        "TeeSqlControlEnvelope(bytes32 clusterId,bytes32[] targetMembers,bytes32 instructionId,uint64 nonce,uint256 chainId,uint64 expiry,bytes32 salt,bytes32 ciphertextHash)"
    );

    /// @dev Domain typehash. No `version` field — see contract docstring
    ///      for the rationale.
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

    /// @dev Hashed domain `name` constant. Splitting it out of the
    ///      digest path lets the compiler precompute it.
    bytes32 internal constant DOMAIN_NAME_HASH = keccak256("TeeSqlControlPlane");

    /// @notice Hash the typed-envelope struct (without the EIP-712
    ///         domain wrap). Useful for tests + off-chain tooling that
    ///         want to inspect the inner hash separately.
    function structHash(ControlEnvelope memory env) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TYPEHASH,
                env.clusterId,
                keccak256(abi.encodePacked(env.targetMembers)),
                env.instructionId,
                env.nonce,
                env.chainId,
                env.expiry,
                env.salt,
                keccak256(env.ciphertext)
            )
        );
    }

    /// @notice Hash the EIP-712 domain separator pinned to
    ///         `verifyingContract` and `block.chainid`.
    /// @dev    The `chainId` baked into the domain is `block.chainid`
    ///         at the moment of digest computation (i.e. on chain at
    ///         `submitControl` time). The envelope's own `chainId`
    ///         field is checked separately by the facet's validation
    ///         pipeline (§5.5 step 2) — we deliberately pin the
    ///         domain to live `block.chainid` so a fork producing
    ///         signatures against the new chain id is rejected
    ///         without relying on signers to correctly populate
    ///         `env.chainId`.
    function domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, DOMAIN_NAME_HASH, block.chainid, verifyingContract));
    }

    /// @notice Full EIP-712 digest the ClusterOwnerSafe signs.
    ///         Pinned to the calling diamond + chain via the domain.
    function digest(ControlEnvelope memory env, address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(verifyingContract), structHash(env)));
    }
}

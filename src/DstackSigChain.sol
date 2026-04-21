// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IKmsRootRegistry
/// @notice Minimal interface the signing-chain verifier uses to ask a caller contract
///         whether a recovered KMS root address is allowed. Lets the library stay pure
///         while storage lives in the caller.
interface IKmsRootRegistry {
    function allowedKmsRoots(address root) external view returns (bool);
}

/// @title DstackSigChain
/// @notice Pure library that verifies the dstack 3-level KMS signature chain:
///         KMS root -> app key -> derived key -> registration message.
/// @dev    Refactored from the prior DstackVerifier contract. No storage. Caller
///         passes an IKmsRootRegistry contract (themselves, typically) so the library
///         can check which KMS root signers are trusted in the current cluster.
library DstackSigChain {
    /// @notice A proof presented by a CVM sidecar. `codeId` is bytes20(app_id) left-aligned.
    struct Proof {
        bytes32 codeId;
        bytes32 messageHash;
        bytes messageSignature;
        bytes appSignature;
        bytes kmsSignature;
        bytes derivedCompressedPubkey; // 33-byte compressed SEC1
        bytes appCompressedPubkey; // 33-byte compressed SEC1
        string purpose;
    }

    error InvalidSigChain();
    error BadSignatureLength();
    error BadPubkey();

    /// @notice Verify a proof. Reverts on failure. On success returns the codeId (as passed in,
    ///         which the caller should validate against their passthrough registry) and the
    ///         33-byte compressed derived pubkey.
    function verify(Proof memory p, IKmsRootRegistry registry)
        internal
        view
        returns (bytes32 codeId, bytes memory derivedPubkey)
    {
        // codeId = bytes32(bytes20(appId)): address occupies the top 20 bytes,
        // bottom 12 bytes must be zero. bytes20(p.codeId) below relies on this
        // layout (it takes the leftmost 20 bytes), as does the KMS signature
        // which was computed over the raw 20-byte app_id in dstack.
        if ((uint256(p.codeId) << 160) != 0) revert InvalidSigChain();

        // Step 1: App key signs "purpose:derivedPubkeyHex" -> recover app EOA
        address recoveredApp;
        {
            string memory derivedHex = _bytesToHex(p.derivedCompressedPubkey);
            bytes32 appMsgHash = keccak256(bytes(abi.encodePacked(p.purpose, ":", derivedHex)));
            recoveredApp = _recoverSigner(appMsgHash, p.appSignature);
        }

        // Step 2: KMS root signs "dstack-kms-issued:" || bytes20(appId) || appPubkey
        {
            bytes32 kmsMsgHash =
                keccak256(abi.encodePacked("dstack-kms-issued:", bytes20(p.codeId), p.appCompressedPubkey));
            address kmsSigner = _recoverSigner(kmsMsgHash, p.kmsSignature);
            if (!registry.allowedKmsRoots(kmsSigner)) revert InvalidSigChain();
        }

        // Step 3: Derived key signs messageHash (EIP-191)
        {
            bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", p.messageHash));
            address messageSigner = _recoverSigner(ethHash, p.messageSignature);
            if (messageSigner != _compressedPubkeyToAddress(p.derivedCompressedPubkey)) revert InvalidSigChain();
        }

        // Step 4: App pubkey matches recovered app signer
        if (recoveredApp != _compressedPubkeyToAddress(p.appCompressedPubkey)) revert InvalidSigChain();

        return (p.codeId, p.derivedCompressedPubkey);
    }

    /// @notice Recover signer from a pre-hashed message and 65-byte sig.
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        return _recoverSigner(hash, sig);
    }

    /// @notice Compute the EOA address of a 33-byte compressed SEC1 pubkey.
    /// @dev    staticcall to modexp precompile (0x05) for the y-coordinate square root.
    function compressedToAddress(bytes memory pubkey) internal view returns (address) {
        return _compressedPubkeyToAddress(pubkey);
    }

    // --- internals ---

    function _recoverSigner(bytes32 hash, bytes memory sig) private pure returns (address) {
        if (sig.length != 65) revert BadSignatureLength();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        return ecrecover(hash, v, r, s);
    }

    function _compressedPubkeyToAddress(bytes memory pubkey) private view returns (address) {
        if (pubkey.length != 33) revert BadPubkey();
        uint8 prefix = uint8(pubkey[0]);
        if (prefix != 0x02 && prefix != 0x03) revert BadPubkey();

        uint256 x;
        assembly {
            x := mload(add(pubkey, 33))
        }

        // secp256k1 field prime
        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 y2 = addmod(mulmod(mulmod(x, x, p), x, p), 7, p);
        uint256 y = _modExp(y2, (p + 1) / 4, p);

        if ((prefix == 0x02 && y % 2 != 0) || (prefix == 0x03 && y % 2 == 0)) {
            y = p - y;
        }

        bytes32 h = keccak256(abi.encodePacked(x, y));
        return address(uint160(uint256(h)));
    }

    function _modExp(uint256 base, uint256 exp, uint256 mod) private view returns (uint256) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exp, mod);
        bytes memory output = new bytes(32);
        assembly {
            if iszero(staticcall(gas(), 0x05, add(input, 32), 192, add(output, 32), 32)) { revert(0, 0) }
        }
        return abi.decode(output, (uint256));
    }

    function _bytesToHex(bytes memory data) private pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
}

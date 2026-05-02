// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDstackKmsAdapter, IDstackKms} from "../../interfaces/IDstackKmsAdapter.sol";
import {IAdmin} from "../../interfaces/IAdmin.sol";
import {DstackSigChain} from "../../DstackSigChain.sol";
import {KmsDstackStorage} from "../../storage/KmsDstackStorage.sol";

/// @title DstackKmsAdapterFacet
/// @notice Diamond facet implementing the dstack-KMS adapter. Owns
///         `teesql.storage.Kms.Dstack` namespace.
/// @dev    Selectors namespaced `dstack_kms_*` per spec §13.1. Cross-facet
///         logic hops via same-diamond dispatch (`address(this)`) per §13.4.
///         Sig-chain verification inlines `DstackSigChain.verify`'s logic
///         instead of calling the library's registry-aware entry point —
///         avoids a selector-collision risk on `allowedKmsRoots(address)` at
///         the diamond surface (we expose `dstack_kms_allowedRoots` only).
///         The pure helpers `recover` + `compressedToAddress` are still
///         delegated to the library (they touch no registry).
///         KMS id pinned in spec §19.1.
contract DstackKmsAdapterFacet is IDstackKmsAdapter {
    /// @notice keccak256("teesql.kms.dstack") — pinned in spec §19.1.
    bytes32 public constant DSTACK_KMS_ID = 0xea3b7f2cbbf5315c63b218799434c030d178fb226a363f7a57c82e25ccff0fd7;

    // --- Events ---
    event KmsSet(address indexed kms);
    event KmsRootAdded(address indexed root);
    event KmsRootRemoved(address indexed root);

    // --- Errors ---
    error ZeroAddress();
    error InvalidSigChain();

    // ─── dstack_kms_* namespaced surface ───────────────────────────────────
    // No un-namespaced selectors per spec §13.1 — they would collide on
    // the diamond if a second KMS adapter were added.

    function dstack_kms_id() external pure override returns (bytes32) {
        return DSTACK_KMS_ID;
    }

    function dstack_kms_verifySigChain(bytes calldata proof)
        external
        view
        override
        returns (bytes32 codeId, bytes memory derivedPubkey)
    {
        return _verifySigChain(proof);
    }

    /// @dev TODO: consider gating to require caller via createMember dispatch
    ///      path. Today CoreFacet is the only legitimate caller; over-gating
    ///      here would break the same-diamond delegation chain (the original
    ///      operator call surfaces as msg.sender, not the facet address).
    function dstack_kms_registerApp(address passthrough) external override {
        _registerApp(passthrough);
    }

    function dstack_kms_setKms(address newKms) external override {
        IAdmin(address(this)).requireOwnerOrPassthrough(msg.sender);
        if (newKms == address(0)) revert ZeroAddress();
        KmsDstackStorage.layout().kms = newKms;
        emit KmsSet(newKms);
    }

    function dstack_kms_kms() external view override returns (address) {
        return KmsDstackStorage.layout().kms;
    }

    function dstack_kms_addRoot(address root) external override {
        IAdmin(address(this)).requireOwnerOrPassthrough(msg.sender);
        if (root == address(0)) revert ZeroAddress();
        KmsDstackStorage.layout().allowedKmsRoots[root] = true;
        emit KmsRootAdded(root);
    }

    function dstack_kms_removeRoot(address root) external override {
        IAdmin(address(this)).requireOwnerOrPassthrough(msg.sender);
        KmsDstackStorage.layout().allowedKmsRoots[root] = false;
        emit KmsRootRemoved(root);
    }

    function dstack_kms_allowedRoots(address root) external view override returns (bool) {
        return KmsDstackStorage.layout().allowedKmsRoots[root];
    }

    function dstack_kms_version() external pure override returns (uint256) {
        return 1;
    }

    // ─── Internals ─────────────────────────────────────────────────────────

    /// @dev Inlines `DstackSigChain.verify`'s 3-step verification so this
    ///      facet reads `KmsDstackStorage.allowedKmsRoots` directly rather
    ///      than via an `IKmsRootRegistry` callback (which would require us
    ///      to expose a non-namespaced `allowedKmsRoots(address)` selector
    ///      on the diamond, defeating the namespacing discipline of §13.1).
    ///      Pure helpers (`recover`, `compressedToAddress`) still live in
    ///      the library — they touch no registry state.
    function _verifySigChain(bytes calldata proof) private view returns (bytes32 codeId, bytes memory derivedPubkey) {
        DstackSigChain.Proof memory p = abi.decode(proof, (DstackSigChain.Proof));

        // codeId = bytes32(bytes20(appId)): top 20 bytes carry the address,
        // bottom 12 must be zero. Mirrors DstackSigChain.verify.
        if ((uint256(p.codeId) << 160) != 0) revert InvalidSigChain();

        // Step 1: app key signs "purpose:derivedPubkeyHex" → recover app EOA
        address recoveredApp;
        {
            string memory derivedHex = _bytesToHex(p.derivedCompressedPubkey);
            bytes32 appMsgHash = keccak256(bytes(abi.encodePacked(p.purpose, ":", derivedHex)));
            recoveredApp = DstackSigChain.recover(appMsgHash, p.appSignature);
        }

        // Step 2: KMS root signs "dstack-kms-issued:" || bytes20(appId) || appPubkey.
        //         Recovered KMS signer must be in our allowedKmsRoots set.
        {
            bytes32 kmsMsgHash =
                keccak256(abi.encodePacked("dstack-kms-issued:", bytes20(p.codeId), p.appCompressedPubkey));
            address kmsSigner = DstackSigChain.recover(kmsMsgHash, p.kmsSignature);
            if (!KmsDstackStorage.layout().allowedKmsRoots[kmsSigner]) revert InvalidSigChain();
        }

        // Step 3: derived key signs messageHash (EIP-191).
        {
            bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", p.messageHash));
            address messageSigner = DstackSigChain.recover(ethHash, p.messageSignature);
            if (messageSigner != DstackSigChain.compressedToAddress(p.derivedCompressedPubkey)) {
                revert InvalidSigChain();
            }
        }

        // Step 4: app pubkey matches recovered app signer.
        if (recoveredApp != DstackSigChain.compressedToAddress(p.appCompressedPubkey)) {
            revert InvalidSigChain();
        }

        return (p.codeId, p.derivedCompressedPubkey);
    }

    function _registerApp(address passthrough) private {
        IDstackKms(KmsDstackStorage.layout().kms).registerApp(passthrough);
    }

    /// @dev Local copy of DstackSigChain._bytesToHex (private in the library).
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

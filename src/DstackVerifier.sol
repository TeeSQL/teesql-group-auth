// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {IVerifier} from "./IVerifier.sol";

/// @title DstackVerifier
/// @notice Verifies the dstack 3-level KMS signature chain:
///         KMS root -> app key -> derived key -> registration message.
/// @dev    Forked from sxysun's DstackVerifier at github.com/Account-Link/tee-interop,
///         wrapped in UUPS+Ownable so we can add new trusted KMS roots (Phala,
///         Secret Network, self-hosted, etc.) under our Safe+Timelock governance.
contract DstackVerifier is IVerifier, Initializable, UUPSUpgradeable, OwnableUpgradeable {
    /// @notice Trusted KMS root signer addresses. Adding a root lets any CVM
    ///         whose KMS is signed by that root participate in the bridge.
    mapping(address => bool) public allowedKmsRoots;

    struct DstackProof {
        bytes32 messageHash;
        bytes messageSignature;
        bytes appSignature;
        bytes kmsSignature;
        bytes derivedCompressedPubkey; // 33 bytes compressed SEC1
        bytes appCompressedPubkey; // 33 bytes compressed SEC1
        string purpose;
    }

    event KmsRootAdded(address indexed root);
    event KmsRootRemoved(address indexed root);

    error InvalidDstackSignature();
    error ZeroAddress();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner, address[] calldata _kmsRoots) external initializer {
        if (_owner == address(0)) revert ZeroAddress();
        __Ownable_init(_owner);

        for (uint256 i = 0; i < _kmsRoots.length; i++) {
            if (_kmsRoots[i] == address(0)) revert ZeroAddress();
            allowedKmsRoots[_kmsRoots[i]] = true;
            emit KmsRootAdded(_kmsRoots[i]);
        }
    }

    function addKmsRoot(address root) external onlyOwner {
        if (root == address(0)) revert ZeroAddress();
        allowedKmsRoots[root] = true;
        emit KmsRootAdded(root);
    }

    function removeKmsRoot(address root) external onlyOwner {
        allowedKmsRoots[root] = false;
        emit KmsRootRemoved(root);
    }

    /// @inheritdoc IVerifier
    function verify(bytes calldata proof)
        external
        view
        override
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        (bytes32 _codeId, DstackProof memory p) = abi.decode(proof, (bytes32, DstackProof));
        if (!_verifyDstackChain(_codeId, p)) revert InvalidDstackSignature();
        return (_codeId, p.derivedCompressedPubkey, "");
    }

    /// @inheritdoc IVerifier
    function verifyAndCache(bytes calldata proof)
        external
        override
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        return this.verify(proof);
    }

    /// @dev 3-level chain: derived key -> app key -> KMS root
    ///      Step 1: App signs "purpose:derivedPubkeyHex" => recover app address
    ///      Step 2: KMS signs "dstack-kms-issued:" + bytes20(appId) + appPubkey => must be trusted root
    ///      Step 3: Derived key signs the message (EIP-191) => must match derivedCompressedPubkey
    ///      Step 4: Recovered app address must match appCompressedPubkey
    function _verifyDstackChain(bytes32 _appId, DstackProof memory p) internal view returns (bool) {
        // Step 1: App signs "purpose:derivedPubkeyHex"
        address recoveredApp;
        {
            string memory derivedHex = _bytesToHex(p.derivedCompressedPubkey);
            bytes32 appMsgHash = keccak256(bytes(abi.encodePacked(p.purpose, ":", derivedHex)));
            recoveredApp = _recoverSigner(appMsgHash, p.appSignature);
        }

        // Step 2: KMS signs "dstack-kms-issued:" + bytes20(appId) + appPubkey
        {
            // Validate that appId can be safely cast to bytes20 (address)
            // Check that upper 12 bytes are zero to prevent data loss
            if (bytes32(_appId) >> 160 != 0) return false;

            bytes32 kmsMsgHash =
                keccak256(abi.encodePacked("dstack-kms-issued:", bytes20(_appId), p.appCompressedPubkey));
            if (!allowedKmsRoots[_recoverSigner(kmsMsgHash, p.kmsSignature)]) return false;
        }

        // Step 3: Derived key signs the message (EIP-191)
        {
            bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", p.messageHash));
            address messageSigner = _recoverSigner(ethHash, p.messageSignature);
            if (messageSigner != _compressedPubkeyToAddress(p.derivedCompressedPubkey)) return false;
        }

        // Step 4: App pubkey matches recovered app signer
        if (recoveredApp != _compressedPubkeyToAddress(p.appCompressedPubkey)) return false;

        return true;
    }

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig len");
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

    function _compressedPubkeyToAddress(bytes memory pubkey) internal view returns (address) {
        require(pubkey.length == 33, "need compressed pubkey");
        uint8 prefix = uint8(pubkey[0]);
        require(prefix == 0x02 || prefix == 0x03, "invalid prefix");

        uint256 x;
        assembly {
            x := mload(add(pubkey, 33))
        }

        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 y2 = addmod(mulmod(mulmod(x, x, p), x, p), 7, p);
        uint256 y = _modExp(y2, (p + 1) / 4, p);

        if ((prefix == 0x02 && y % 2 != 0) || (prefix == 0x03 && y % 2 == 0)) {
            y = p - y;
        }

        bytes32 hash = keccak256(abi.encodePacked(x, y));
        return address(uint160(uint256(hash)));
    }

    function _modExp(uint256 base, uint256 exp, uint256 mod) internal view returns (uint256) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exp, mod);
        bytes memory output = new bytes(32);
        assembly {
            if iszero(staticcall(gas(), 0x05, add(input, 32), 192, add(output, 32), 32)) { revert(0, 0) }
        }
        return abi.decode(output, (uint256));
    }

    function _bytesToHex(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            str[i * 2] = alphabet[uint8(data[i] >> 4)];
            str[i * 2 + 1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    // --- UUPS ---

    function _authorizeUpgrade(address) internal override onlyOwner {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @title TeeGroupAuth
/// @notice Peer network membership for Dstack TEEs with multi-KMS root support
/// @dev Members prove code identity via KMS signature chain (dstack).
///      Any verified member can onboard new members by posting encrypted group secrets.
///      Uses UUPS upgradeable proxy pattern.
contract TeeGroupAuth is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    // --- Storage ---

    /// @notice Trusted KMS root signers (multi-root support)
    mapping(address => bool) public trustedKmsRoots;

    /// @notice Allowed code identities (appId / composeHash)
    mapping(bytes32 => bool) public allowedCode;

    /// @notice Current secret version, starts at 1
    uint256 public secretVersion;

    struct Member {
        bytes32 codeId;
        bytes pubkey;
        uint256 registeredAt;
    }

    /// @dev memberId = keccak256(pubkey)
    mapping(bytes32 => Member) internal _members;

    struct OnboardMsg {
        bytes32 fromMember;
        bytes encryptedPayload;
    }
    mapping(bytes32 => OnboardMsg[]) internal _onboarding;

    struct DstackProof {
        bytes32 messageHash;
        bytes messageSignature;
        bytes appSignature;
        bytes kmsSignature;
        bytes derivedCompressedPubkey;  // 33 bytes compressed SEC1
        bytes appCompressedPubkey;      // 33 bytes compressed SEC1
        string purpose;
    }

    // --- Events ---

    event MemberRegistered(bytes32 indexed memberId, bytes32 indexed codeId, bytes pubkey);
    event MemberRevoked(bytes32 indexed memberId);
    event OnboardingPosted(bytes32 indexed toMember, bytes32 indexed fromMember, uint256 secretVersion);
    event AllowedCodeAdded(bytes32 indexed codeId);
    event AllowedCodeRemoved(bytes32 indexed codeId);
    event TrustedKmsRootAdded(address indexed root);
    event TrustedKmsRootRemoved(address indexed root);
    event SecretRotated(uint256 newVersion);

    // --- Errors ---

    error CodeNotAllowed();
    error AlreadyRegistered();
    error MemberNotFound();
    error InvalidDstackSignature();
    error ZeroAddress();
    error SenderNotFromMember();

    // --- Initializer ---

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract (replaces constructor for proxy pattern)
    /// @param _owner The owner address
    /// @param _trustedKmsRoots Initial set of trusted KMS root addresses
    /// @param _allowedCodes Initial set of allowed code identities
    function initialize(
        address _owner,
        address[] calldata _trustedKmsRoots,
        bytes32[] calldata _allowedCodes
    ) external initializer {
        __Ownable_init(_owner);

        secretVersion = 1;

        for (uint256 i = 0; i < _trustedKmsRoots.length; i++) {
            if (_trustedKmsRoots[i] == address(0)) revert ZeroAddress();
            trustedKmsRoots[_trustedKmsRoots[i]] = true;
            emit TrustedKmsRootAdded(_trustedKmsRoots[i]);
        }

        for (uint256 i = 0; i < _allowedCodes.length; i++) {
            allowedCode[_allowedCodes[i]] = true;
            emit AllowedCodeAdded(_allowedCodes[i]);
        }
    }

    // --- Admin ---

    function addTrustedKmsRoot(address root) external onlyOwner {
        if (root == address(0)) revert ZeroAddress();
        trustedKmsRoots[root] = true;
        emit TrustedKmsRootAdded(root);
    }

    function removeTrustedKmsRoot(address root) external onlyOwner {
        trustedKmsRoots[root] = false;
        emit TrustedKmsRootRemoved(root);
    }

    function addAllowedCode(bytes32 codeId) external onlyOwner {
        allowedCode[codeId] = true;
        emit AllowedCodeAdded(codeId);
    }

    function removeAllowedCode(bytes32 codeId) external onlyOwner {
        allowedCode[codeId] = false;
        emit AllowedCodeRemoved(codeId);
    }

    function revokeMember(bytes32 memberId) external onlyOwner {
        if (_members[memberId].registeredAt == 0) revert MemberNotFound();
        delete _members[memberId];
        emit MemberRevoked(memberId);
    }

    function rotateSecret() external onlyOwner {
        secretVersion++;
        emit SecretRotated(secretVersion);
    }

    // --- Registration ---

    /// @notice Register via Dstack KMS signature chain
    /// @dev Pubkey is derived from the DstackProof's derivedCompressedPubkey.
    ///      The KMS chain proves the TEE controls this key.
    /// @param codeId The appId/composeHash
    /// @param dstackProof The 3-level signature chain proof
    function registerDstack(
        bytes32 codeId,
        DstackProof calldata dstackProof
    ) external returns (bytes32) {
        if (!_verifyDstackChain(codeId, dstackProof)) revert InvalidDstackSignature();
        if (!allowedCode[codeId]) revert CodeNotAllowed();
        return _register(codeId, dstackProof.derivedCompressedPubkey);
    }

    function _register(bytes32 codeId, bytes calldata pubkey) internal returns (bytes32 memberId) {
        memberId = keccak256(pubkey);
        if (_members[memberId].registeredAt != 0) revert AlreadyRegistered();
        _members[memberId] = Member({codeId: codeId, pubkey: pubkey, registeredAt: block.timestamp});
        emit MemberRegistered(memberId, codeId, pubkey);
    }

    // --- Onboarding ---

    /// @notice Post encrypted group secret for a new member
    /// @dev Sender must be the address derived from fromMember's pubkey to prevent spoofing.
    ///      The payload is encrypted to the recipient's pubkey.
    function onboard(bytes32 fromMemberId, bytes32 toMemberId, bytes calldata encryptedPayload) external {
        Member storage from = _members[fromMemberId];
        if (from.registeredAt == 0) revert MemberNotFound();
        if (_members[toMemberId].registeredAt == 0) revert MemberNotFound();

        // Verify msg.sender controls the fromMember's key
        if (msg.sender != _compressedPubkeyToAddress(from.pubkey)) revert SenderNotFromMember();

        _onboarding[toMemberId].push(OnboardMsg({fromMember: fromMemberId, encryptedPayload: encryptedPayload}));
        emit OnboardingPosted(toMemberId, fromMemberId, secretVersion);
    }

    // --- Views ---

    function getMember(bytes32 memberId) external view returns (bytes32 codeId, bytes memory pubkey, uint256 registeredAt) {
        Member storage m = _members[memberId];
        return (m.codeId, m.pubkey, m.registeredAt);
    }

    function isMember(bytes32 memberId) external view returns (bool) {
        return _members[memberId].registeredAt != 0;
    }

    function getOnboarding(bytes32 memberId) external view returns (OnboardMsg[] memory) {
        return _onboarding[memberId];
    }

    // --- UUPS ---

    function _authorizeUpgrade(address) internal override onlyOwner {}

    // --- Dstack signature chain verification ---

    /// @dev 3-level chain: derived key -> app key -> KMS root
    ///      Step 1: App signs "purpose:derivedPubkeyHex" => recover app address
    ///      Step 2: KMS signs "dstack-kms-issued:" + bytes20(appId) + appPubkey => must be trusted root
    ///      Step 3: Derived key signs the message (EIP-191) => must match derivedCompressedPubkey
    ///      Step 4: Recovered app address must match appCompressedPubkey
    function _verifyDstackChain(bytes32 _appId, DstackProof calldata p) internal view returns (bool) {
        // Step 1: App signs "purpose:derivedPubkeyHex"
        address recoveredApp;
        {
            string memory derivedHex = _bytesToHex(p.derivedCompressedPubkey);
            bytes32 appMsgHash = keccak256(bytes(abi.encodePacked(p.purpose, ":", derivedHex)));
            recoveredApp = _recoverSigner(appMsgHash, p.appSignature);
        }

        // Step 2: KMS signs "dstack-kms-issued:" + bytes20(appId) + appPubkey
        {
            bytes32 kmsMsgHash = keccak256(abi.encodePacked(
                "dstack-kms-issued:", bytes20(_appId), p.appCompressedPubkey
            ));
            if (!trustedKmsRoots[_recoverSigner(kmsMsgHash, p.kmsSignature)]) return false;
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

    function _recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig len");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        return ecrecover(hash, v, r, s);
    }

    function _compressedPubkeyToAddress(bytes memory pubkey) internal view returns (address) {
        require(pubkey.length == 33, "need compressed pubkey");
        uint8 prefix = uint8(pubkey[0]);
        require(prefix == 0x02 || prefix == 0x03, "invalid prefix");

        uint256 x;
        assembly { x := mload(add(pubkey, 33)) }

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

    function _bytesToHex(bytes calldata data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(data.length * 2);
        for (uint256 i = 0; i < data.length; i++) {
            str[i*2] = alphabet[uint8(data[i] >> 4)];
            str[i*2+1] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
}

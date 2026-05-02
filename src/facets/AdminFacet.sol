// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDiamondReadable} from "@solidstate/contracts/proxy/diamond/readable/IDiamondReadable.sol";
import {OwnableStorage} from "@solidstate/contracts/access/ownable/OwnableStorage.sol";

import {IAdmin} from "../interfaces/IAdmin.sol";
import {CoreStorage} from "../storage/CoreStorage.sol";
import {AdapterRegistryStorage} from "../storage/AdapterRegistryStorage.sol";
import {AllowlistsStorage} from "../storage/AllowlistsStorage.sol";
import {LifecycleStorage} from "../storage/LifecycleStorage.sol";

/// @title AdminFacet
/// @notice Cluster-wide governance. All selectors are bare (provider-agnostic).
/// @dev    Cluster owner authority lives in solidstate's `OwnableStorage`
///         (single slot, pre-registered on the diamond by SolidStateDiamond's
///         constructor as the `owner()` / `transferOwnership` / `acceptOwnership`
///         / `nomineeOwner` selectors). AdminFacet's auth helpers
///         (`requireOwner`, `requireOwnerOrPassthrough`) read the same slot via
///         `OwnableStorage.layout().owner` so all owner checks across all
///         facets agree on a single source of truth.
contract AdminFacet is IAdmin {
    // --- Events not declared on IAdmin (kept here for ABI completeness) ---
    event Paused(address indexed account);
    event Unpaused(address indexed account);
    event ClusterDestroyed(uint256 timestamp);
    event MemberRetired(bytes32 indexed memberId, uint256 timestamp);

    error AlreadyDestroyed();
    error AlreadyRetired();
    error UnknownMember();
    error CannotRetireLeader();

    function _$() private pure returns (CoreStorage.Layout storage) {
        return CoreStorage.layout();
    }

    function _ownerAddr() private view returns (address) {
        return OwnableStorage.layout().owner;
    }

    modifier onlyOwner() {
        if (msg.sender != _ownerAddr()) revert NotAuthorized();
        _;
    }

    modifier onlyPauser() {
        if (msg.sender != _$().pauser) revert NotAuthorized();
        _;
    }

    modifier whenNotDestroyed() {
        if (LifecycleStorage.layout().destroyedAt != 0) revert AlreadyDestroyed();
        _;
    }

    // --- Pause (cluster-wide) ---

    function pauser() external view returns (address) {
        return _$().pauser;
    }

    function setPauser(address newPauser) external onlyOwner whenNotDestroyed {
        if (newPauser == address(0)) revert ZeroAddress();
        _$().pauser = newPauser;
        emit PauserSet(newPauser);
    }

    function pause() external onlyPauser {
        _$().paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        _$().paused = false;
        emit Unpaused(msg.sender);
    }

    function paused() external view returns (bool) {
        return _$().paused;
    }

    // --- Cluster-wide allowlists ---

    function addComposeHash(bytes32 h) external whenNotDestroyed {
        _requireOwnerOrPassthrough(msg.sender);
        AllowlistsStorage.layout().allowedComposeHashes[h] = true;
        emit ComposeHashAdded(h);
    }

    function removeComposeHash(bytes32 h) external whenNotDestroyed {
        _requireOwnerOrPassthrough(msg.sender);
        AllowlistsStorage.layout().allowedComposeHashes[h] = false;
        emit ComposeHashRemoved(h);
    }

    function addDevice(bytes32 d) external whenNotDestroyed {
        _requireOwnerOrPassthrough(msg.sender);
        AllowlistsStorage.layout().allowedDeviceIds[d] = true;
        emit DeviceAdded(d);
    }

    function removeDevice(bytes32 d) external whenNotDestroyed {
        _requireOwnerOrPassthrough(msg.sender);
        AllowlistsStorage.layout().allowedDeviceIds[d] = false;
        emit DeviceRemoved(d);
    }

    function setAllowAnyDevice(bool v) external whenNotDestroyed {
        _requireOwnerOrPassthrough(msg.sender);
        AllowlistsStorage.layout().allowAnyDevice = v;
        emit AllowAnyDeviceSet(v);
    }

    function authorizeSigner(address signer, uint8 permissions) external onlyOwner whenNotDestroyed {
        if (signer == address(0)) revert ZeroAddress();
        if (permissions == 0 || permissions > 3) revert BadPerms();
        AllowlistsStorage.layout().authorizedSigners[signer] =
            AllowlistsStorage.AuthorizedSigner({permissions: permissions, active: true, authorizedAt: block.timestamp});
        emit SignerAuthorized(signer, permissions);
    }

    function revokeSigner(address signer) external onlyOwner whenNotDestroyed {
        AllowlistsStorage.layout().authorizedSigners[signer].active = false;
        emit SignerRevoked(signer);
    }

    // --- Two-axis adapter management ---

    function registerAttestationAdapter(bytes32 attestationId, address facet) external onlyOwner whenNotDestroyed {
        if (attestationId == bytes32(0) || facet == address(0)) revert ZeroAddress();
        AdapterRegistryStorage.Layout storage a = AdapterRegistryStorage.layout();
        if (a.attestationFacet[attestationId] == address(0)) {
            a.attestationIds.push(attestationId);
        }
        a.attestationFacet[attestationId] = facet;
        a.attestationRegistered[attestationId] = true;
        emit AttestationAdapterRegistered(attestationId, facet);
    }

    function deregisterAttestationAdapter(bytes32 attestationId) external onlyOwner {
        AdapterRegistryStorage.Layout storage a = AdapterRegistryStorage.layout();
        if (!a.attestationRegistered[attestationId]) revert NotRegistered();
        a.attestationRegistered[attestationId] = false;
        emit AttestationAdapterDeregistered(attestationId);
    }

    function setDefaultAttestationAdapter(bytes32 attestationId) external onlyOwner {
        AdapterRegistryStorage.Layout storage a = AdapterRegistryStorage.layout();
        if (!a.attestationRegistered[attestationId]) revert NotRegistered();
        a.defaultAttestationId = attestationId;
        emit DefaultAttestationSet(attestationId);
    }

    function registerKmsAdapter(bytes32 kmsId, address facet) external onlyOwner whenNotDestroyed {
        if (kmsId == bytes32(0) || facet == address(0)) revert ZeroAddress();
        AdapterRegistryStorage.Layout storage a = AdapterRegistryStorage.layout();
        if (a.kmsFacet[kmsId] == address(0)) {
            a.kmsIds.push(kmsId);
        }
        a.kmsFacet[kmsId] = facet;
        a.kmsRegistered[kmsId] = true;
        emit KmsAdapterRegistered(kmsId, facet);
    }

    function deregisterKmsAdapter(bytes32 kmsId) external onlyOwner {
        AdapterRegistryStorage.Layout storage a = AdapterRegistryStorage.layout();
        if (!a.kmsRegistered[kmsId]) revert NotRegistered();
        a.kmsRegistered[kmsId] = false;
        emit KmsAdapterDeregistered(kmsId);
    }

    function setDefaultKmsAdapter(bytes32 kmsId) external onlyOwner {
        AdapterRegistryStorage.Layout storage a = AdapterRegistryStorage.layout();
        if (!a.kmsRegistered[kmsId]) revert NotRegistered();
        a.defaultKmsId = kmsId;
        emit DefaultKmsSet(kmsId);
    }

    // --- Lifecycle ---
    // TODO(integration): see header note. CoreFacet has been told to
    // implement these as well; expected selector collision at diamondCut.

    function destroy() external onlyOwner {
        LifecycleStorage.Layout storage l = LifecycleStorage.layout();
        if (l.destroyedAt != 0) revert AlreadyDestroyed();
        l.destroyedAt = block.timestamp;
        emit ClusterDestroyed(block.timestamp);
    }

    function retireMember(bytes32 memberId) external onlyOwner {
        CoreStorage.Layout storage s = _$();
        if (s.members[memberId].instanceId == address(0)) revert UnknownMember();
        LifecycleStorage.Layout storage l = LifecycleStorage.layout();
        if (l.memberRetiredAt[memberId] != 0) revert AlreadyRetired();
        if (memberId == s.leaderMemberId) revert CannotRetireLeader();
        l.memberRetiredAt[memberId] = block.timestamp;
        emit MemberRetired(memberId, block.timestamp);
    }

    // --- Diamond version surfaces ---

    function clusterVersion() external view returns (uint256) {
        return _$().clusterVersion;
    }

    function facetBundleHash() external view returns (bytes32) {
        return keccak256(abi.encode(IDiamondReadable(address(this)).facets()));
    }

    // --- Auth helpers (callable by other facets via diamond dispatch) ---

    function requireOwner(address caller) external view {
        if (caller != _ownerAddr()) revert NotAuthorized();
    }

    function requireOwnerOrPassthrough(address caller) external view {
        _requireOwnerOrPassthrough(caller);
    }

    function _requireOwnerOrPassthrough(address caller) private view {
        if (caller != _ownerAddr() && !_$().isOurPassthrough[caller]) revert NotAuthorized();
    }
}

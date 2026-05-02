// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ICore} from "../interfaces/ICore.sol";
import {IAdmin} from "../interfaces/IAdmin.sol";
import {IDstackKmsAdapter} from "../interfaces/IDstackKmsAdapter.sol";
import {IDstackAttestationAdapter} from "../interfaces/IDstackAttestationAdapter.sol";
import {IClusterMemberFactory} from "../interfaces/IClusterMemberFactory.sol";
import {CoreStorage} from "../storage/CoreStorage.sol";
import {AdapterRegistryStorage} from "../storage/AdapterRegistryStorage.sol";
import {LifecycleStorage} from "../storage/LifecycleStorage.sol";
import {DstackSigChain} from "../DstackSigChain.sol";

/// @title CoreFacet
/// @notice Provider-agnostic membership / leader / onboarding / lifecycle /
///         factory-orchestration facet of the cluster diamond. Holds no
///         constructor or initializer — DiamondInit seeds CoreStorage
///         during diamond construction.
contract CoreFacet is ICore {
    bytes32 internal constant DSTACK_ATTESTATION_ID =
        0x33a9d6b17861ebd35aca9a68779e7b913c04060dc2f6ab672d9f190a13924d80;
    bytes32 internal constant DSTACK_KMS_ID =
        0xea3b7f2cbbf5315c63b218799434c030d178fb226a363f7a57c82e25ccff0fd7;

    string private constant _REGISTER_MSG_PREFIX = "teesql-cluster-register:v3";
    string private constant _CALL_MSG_PREFIX = "teesql-cluster-call:v1";
    string private constant _WITNESS_MSG_PREFIX = "teesql-leader-offline:v1";

    /// @dev Local revert reason for the cluster-pause gate. Not part of
    ///      ICore's surface — kept on the implementation so the external
    ///      interface stays minimal. Callers only ever see this error
    ///      bubble up from a paused-cluster mutator.
    /// TODO(integration): if AdminFacet ends up canonicalising a pause
    ///      error in IAdmin, switch this to that one and drop the local
    ///      declaration so the diamond surfaces a single error sigid.
    error Paused();

    modifier whenNotPaused() {
        if (_$().paused) revert Paused();
        _;
    }

    modifier whenNotDestroyed() {
        if (LifecycleStorage.layout().destroyedAt != 0) revert ClusterDestroyed_();
        _;
    }

    // --- Membership ---

    function register(RegisterArgs calldata a)
        external
        whenNotPaused
        whenNotDestroyed
        returns (bytes32 memberId)
    {
        // TODO(future-kms-dispatch): hardcoded to the dstack KMS adapter at
        // v4 cutover because it is the only KMS adapter on the diamond. Once
        // a second KmsAdapter ships, this dispatch needs to resolve the
        // namespaced verifier selector dynamically — Core does not know the
        // proof's KMS axis until verifySigChain returns the codeId. The
        // tightest fix is a two-call shape that lets the caller declare the
        // KMS axis in args (a new field on RegisterArgs) so the registry
        // selector for that adapter is invoked, then validated against
        // passthroughToKmsId[passthrough] post-verify.
        (bytes32 codeId, bytes memory derivedPubkey) =
            IDstackKmsAdapter(address(this)).dstack_kms_verifySigChain(a.proof);

        address passthrough = address(bytes20(codeId));
        CoreStorage.Layout storage $ = _$();
        if (!$.isOurPassthrough[passthrough]) revert WrongAppId();

        // Lock new mints to the right verifier when more KMS adapters land.
        // For now this is a tautology (only DSTACK_KMS_ID can be assigned)
        // but the check stays in place so the assertion is wired before the
        // multi-KMS rollout.
        if (AdapterRegistryStorage.layout().passthroughToKmsId[passthrough] != DSTACK_KMS_ID) {
            revert WrongAppId();
        }

        bytes32 bindHash = registrationMessage(a.instanceId, a.endpoint, a.publicEndpoint, a.dnsLabel);
        bytes32 bindEthHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", bindHash));
        address derivedAddr = DstackSigChain.compressedToAddress(derivedPubkey);
        address recovered = DstackSigChain.recover(bindEthHash, a.bindingSig);
        if (recovered != derivedAddr) revert InstanceBindingInvalid();

        memberId = keccak256(derivedPubkey);
        $.members[memberId] = CoreStorage.Member({
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
        $.passthroughToMember[passthrough] = memberId;

        emit MemberRegistered(memberId, a.instanceId, passthrough, a.dnsLabel);
        emit InstanceBindingVerified(memberId, a.instanceId);
    }

    function getMember(bytes32 id) external view returns (CoreStorage.Member memory) {
        return _$().members[id];
    }

    function instanceToMember(address i) external view returns (bytes32) {
        return _$().instanceToMember[i];
    }

    function derivedToMember(address d) external view returns (bytes32) {
        return _$().derivedToMember[d];
    }

    function passthroughToMember(address p) external view returns (bytes32) {
        return _$().passthroughToMember[p];
    }

    function memberNonce(bytes32 m) external view returns (uint256) {
        return _$().memberNonce[m];
    }

    // --- Onboarding ---

    function onboard(CallAuth calldata auth, bytes32 toId, bytes calldata payload)
        external
        whenNotPaused
        whenNotDestroyed
    {
        bytes32 fromId = _verifyCall(auth, this.onboard.selector, abi.encode(toId, payload));
        CoreStorage.Layout storage $ = _$();
        if ($.members[toId].registeredAt == 0) revert NotMember();
        $.onboarding[toId].push(CoreStorage.OnboardMsg({fromMember: fromId, encryptedPayload: payload}));
        emit OnboardingPosted(toId, fromId);
    }

    function getOnboarding(bytes32 id) external view returns (CoreStorage.OnboardMsg[] memory) {
        return _$().onboarding[id];
    }

    // --- Leader ---

    function claimLeader(CallAuth calldata auth, bytes calldata newEndpoint, Witness[] calldata witnesses)
        external
        whenNotPaused
        whenNotDestroyed
    {
        bytes32 memberId = _verifyCall(auth, this.claimLeader.selector, abi.encode(newEndpoint, witnesses));
        CoreStorage.Layout storage $ = _$();

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

    function updateEndpoint(CallAuth calldata auth, bytes calldata newEndpoint)
        external
        whenNotPaused
        whenNotDestroyed
    {
        bytes32 memberId = _verifyCall(auth, this.updateEndpoint.selector, abi.encode(newEndpoint));
        _$().members[memberId].endpoint = newEndpoint;
        emit EndpointUpdated(memberId, newEndpoint);
    }

    function updatePublicEndpoint(CallAuth calldata auth, bytes calldata newPublicEndpoint)
        external
        whenNotPaused
        whenNotDestroyed
    {
        bytes32 memberId = _verifyCall(auth, this.updatePublicEndpoint.selector, abi.encode(newPublicEndpoint));
        _$().members[memberId].publicEndpoint = newPublicEndpoint;
        emit PublicEndpointUpdated(memberId, newPublicEndpoint);
    }

    function currentLeader() external view returns (CoreStorage.Member memory) {
        CoreStorage.Layout storage $ = _$();
        if ($.leaderMemberId == bytes32(0)) revert NotLeaderClaimant();
        return $.members[$.leaderMemberId];
    }

    function leaderLease() external view returns (bytes32 memberId, uint256 epoch) {
        CoreStorage.Layout storage $ = _$();
        return ($.leaderMemberId, $.leaderEpoch);
    }

    // --- Factory orchestration ---

    function createMember(bytes32 salt, bytes32 attestationId, bytes32 kmsId)
        external
        whenNotPaused
        whenNotDestroyed
        returns (address passthrough)
    {
        AdapterRegistryStorage.Layout storage reg = AdapterRegistryStorage.layout();

        bytes32 effectiveAttestation = attestationId == bytes32(0) ? reg.defaultAttestationId : attestationId;
        bytes32 effectiveKms = kmsId == bytes32(0) ? reg.defaultKmsId : kmsId;

        if (!reg.attestationRegistered[effectiveAttestation]) revert AdapterNotRegistered();
        if (!reg.kmsRegistered[effectiveKms]) revert AdapterNotRegistered();

        CoreStorage.Layout storage $ = _$();
        bytes32 effectiveSalt = salt == bytes32(0) ? bytes32(uint256($.nextMemberSeq++)) : salt;

        address factory = $.factory;
        address predicted =
            IClusterMemberFactory(factory).predict(address(this), effectiveSalt, effectiveAttestation);

        reg.passthroughToAttestationId[predicted] = effectiveAttestation;
        reg.passthroughToKmsId[predicted] = effectiveKms;

        passthrough = IClusterMemberFactory(factory).deployMemberWithExpectedImpl(
            address(this),
            effectiveSalt,
            effectiveAttestation,
            IClusterMemberFactory(factory).memberImpl(effectiveAttestation)
        );

        $.isOurPassthrough[passthrough] = true;

        // TODO(future-kms-dispatch): hardcoded to dstack KMS adapter at v4
        // cutover. When other KMS adapters land, resolve the namespaced
        // selector dynamically (e.g. via a registry-managed selector table
        // keyed on kmsId, or a low-level call assembled from a per-adapter
        // selector constant fetched from AdapterRegistryStorage).
        if (effectiveKms == DSTACK_KMS_ID) {
            IDstackKmsAdapter(address(this)).dstack_kms_registerApp(passthrough);
        } else {
            revert AdapterNotRegistered();
        }

        // TODO(future-attestation-dispatch): mirror of the KMS dispatch.
        // dstack_onMemberMinted is a no-op today but the selector lives
        // on the adapter so the same dispatch pattern composes when other
        // runtimes need a real mint hook.
        if (effectiveAttestation == DSTACK_ATTESTATION_ID) {
            IDstackAttestationAdapter(address(this)).dstack_onMemberMinted(passthrough);
        } else {
            revert AdapterNotRegistered();
        }

        emit MemberPassthroughCreated(passthrough, effectiveSalt, effectiveAttestation, effectiveKms);
    }

    function predictMember(bytes32 salt, bytes32 attestationId) external view returns (address) {
        CoreStorage.Layout storage $ = _$();
        AdapterRegistryStorage.Layout storage reg = AdapterRegistryStorage.layout();
        bytes32 effectiveAttestation = attestationId == bytes32(0) ? reg.defaultAttestationId : attestationId;
        bytes32 effectiveSalt = salt == bytes32(0) ? bytes32(uint256($.nextMemberSeq)) : salt;
        return IClusterMemberFactory($.factory).predict(address(this), effectiveSalt, effectiveAttestation);
    }

    function isOurPassthrough(address p) external view returns (bool) {
        return _$().isOurPassthrough[p];
    }

    // Lifecycle mutators (destroy, retireMember) live on AdminFacet —
    // owner-gated governance is its scope. CoreFacet only consumes the
    // lifecycle state via LifecycleStorage in modifiers.

    // --- Per-call auth message helpers ---

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

    // clusterId() lives on ViewFacet — read surface owner.

    // --- Internals ---

    function _verifyCall(CallAuth calldata a, bytes4 selector, bytes memory args) internal returns (bytes32) {
        CoreStorage.Layout storage $ = _$();
        CoreStorage.Member storage m = $.members[a.memberId];
        if (m.registeredAt == 0) revert NotMember();
        if (LifecycleStorage.layout().memberRetiredAt[a.memberId] != 0) revert MemberRetired_();
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

    function _$() private pure returns (CoreStorage.Layout storage) {
        return CoreStorage.layout();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondSmokeTest} from "../test/DiamondSmoke.t.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {ClusterMemberFactory} from "src/ClusterMemberFactory.sol";
import {IClusterMemberFactory, IMemberInit} from "src/interfaces/IClusterMemberFactory.sol";
import {DstackMember} from "src/members/DstackMember.sol";
import {FactoryStorage} from "src/storage/FactoryStorage.sol";

/// @title ClusterMemberFactoryProvenanceTest
/// @notice Coverage for the new `deployedMembers` provenance map +
///         `isDeployedMember` view that the gas-sponsorship webhook
///         consumes. Spec: §3.2 + §3.4 of
///         `cluster-diamond-factory-and-member-provenance.md`.
///
/// The load-bearing property is symmetric to the cluster factory's
/// `isDeployedCluster` invariant: `isDeployedMember(p) == true` iff THIS
/// factory's `deployMember` minted `p`. A proxy at the same address that
/// was deployed any other way (here: directly via
/// `new ERC1967Proxy(impl, initData)`) MUST NOT register, otherwise an
/// attacker could publish a rogue proxy and trick the webhook into
/// sponsoring its UserOps.
///
/// Inherits `DiamondSmokeTest` only for the chain-singleton fixture
/// (`factory` + `dstackMemberImpl`); each test reuses the smoke-test
/// factory rather than deploying its own, since the `isDeployedMember`
/// surface IS the new code path being verified - exercising it through
/// the same factory the rest of the suite uses keeps the verification
/// realistic.
contract ClusterMemberFactoryProvenanceTest is DiamondSmokeTest {
    bytes32 internal constant SOME_SALT = bytes32(uint256(0xABCDEF));

    address internal stranger = address(0xBEEF);

    /// Convenience: the cluster argument is irrelevant to the provenance
    /// bit (the factory writes the bit unconditionally inside `deployMember`
    /// after the proxy is constructed). Use a stable arbitrary address.
    address internal constant FAKE_CLUSTER = address(0xC1A5);

    /// Prime the factory with the dstack runtime impl. Idempotent across
    /// tests (subsequent calls would revert `ImplUnchanged`).
    function _registerDstackImpl() internal {
        if (factory.memberImpl(DSTACK_ATTESTATION_ID) == address(0)) {
            factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));
        }
    }

    // ── Trust-anchor invariants ────────────────────────────────────────────

    /// Pre-deploy state: a not-yet-minted proxy address registers as false.
    /// Combined with `predict()`, callers can pre-check "is this address one
    /// of ours?" before any factory write happens.
    function test_isDeployedMember_returnsFalseBeforeDeploy() public {
        _registerDstackImpl();
        address predicted = factory.predict(FAKE_CLUSTER, SOME_SALT, DSTACK_ATTESTATION_ID);
        assertFalse(factory.isDeployedMember(predicted), "pre-deploy address must register as false");
    }

    /// The minimum requirement: after `deployMember(...)`, the returned
    /// proxy address MUST register as true. If this is broken, every
    /// downstream webhook check rejects every legitimate UserOp.
    function test_deployMember_flipsDeployedMembersTrue() public {
        _registerDstackImpl();
        address proxy = factory.deployMember(FAKE_CLUSTER, SOME_SALT, DSTACK_ATTESTATION_ID);
        assertTrue(factory.isDeployedMember(proxy), "deployedMembers[proxy] must flip true on deploy");
    }

    /// THE load-bearing trust-anchor test for the webhook. A proxy with
    /// IDENTICAL bytecode + storage layout to a factory-minted member but
    /// constructed OUT-OF-BAND (here: `new ERC1967Proxy(...)` directly)
    /// MUST NOT register as factory-deployed. The webhook trusts this
    /// property as the answer to "did our factory mint this member?";
    /// any false positive lets an attacker drain gas sponsorship.
    function test_isDeployedMember_returnsFalseForExternallyDeployedProxy() public {
        _registerDstackImpl();

        // Construct an ERC1967Proxy DIRECTLY - same impl, same init data
        // shape, same bytecode. The factory has no idea about this
        // deployment.
        bytes memory initData = abi.encodeCall(IMemberInit.initialize, (FAKE_CLUSTER));
        ERC1967Proxy externalProxy = new ERC1967Proxy(address(dstackMemberImpl), initData);

        assertFalse(
            factory.isDeployedMember(address(externalProxy)),
            "externally-deployed proxy MUST NOT register as factory-deployed"
        );
        // And the proxy is functional (bytecode populated, initialize ran)
        // - confirming this isn't an artifact of a failed deploy. The
        // factory's defense is purely the `deployedMembers[proxy]` bit;
        // bytecode equivalence does not grant provenance.
        assertEq(
            DstackMember(address(externalProxy)).cluster(),
            FAKE_CLUSTER,
            "external proxy initialized fine - the factory is not consulted"
        );
    }

    /// `deployedMembers[X]` is set inside `deployMember` and never written
    /// again. Verify that calling every external (non-deploy) function on
    /// the factory after a deploy keeps the bit pinned to true.
    function test_deployedMembers_isSetOnly() public {
        _registerDstackImpl();
        address proxy = factory.deployMember(FAKE_CLUSTER, SOME_SALT, DSTACK_ATTESTATION_ID);
        assertTrue(factory.isDeployedMember(proxy), "set after deploy");

        // Pure reads - none of these should mutate the bit.
        factory.admin();
        factory.pendingAdmin();
        factory.memberImpl(DSTACK_ATTESTATION_ID);
        factory.registeredAttestationIds();
        factory.isDeployedMember(proxy);
        factory.predict(FAKE_CLUSTER, bytes32(uint256(2)), DSTACK_ATTESTATION_ID);

        // Mutators that SHOULDN'T touch any deployedMembers entry.
        DstackMember rotated = new DstackMember();
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(rotated));
        // (Restore so subsequent factory.deployMember calls still work
        // against the original impl bake. Not strictly necessary here.)
        factory.setMemberImpl(DSTACK_ATTESTATION_ID, address(dstackMemberImpl));

        factory.transferAdmin(stranger);
        vm.prank(stranger);
        factory.acceptAdmin();
        // Hand back so cleanup teardown stays sane.
        vm.prank(stranger);
        factory.transferAdmin(deployer);
        factory.acceptAdmin();

        // Another deploy with a different salt mustn't touch the prior bit.
        factory.deployMember(FAKE_CLUSTER, bytes32(uint256(99)), DSTACK_ATTESTATION_ID);

        assertTrue(factory.isDeployedMember(proxy), "bit cleared by some factory function: invariant broken");
    }

    /// A genuinely random address (no contract there at all) registers as
    /// false. Sanity that the storage default is the expected zero-init
    /// branch and the factory doesn't accidentally treat unknown addresses
    /// as authorized.
    function test_isDeployedMember_returnsFalseForRandomAddress() public view {
        assertFalse(factory.isDeployedMember(address(0xDEAD)), "random address must register as false");
        assertFalse(factory.isDeployedMember(address(0)), "address(0) must register as false");
        assertFalse(factory.isDeployedMember(stranger), "EOA must register as false");
    }

    /// The atomic `deployMemberWithExpectedImpl` variant flows into
    /// `deployMember` via `return deployMember(...)`, so the writer line
    /// fires regardless of which entrypoint is used. Verify both paths
    /// land the bit so the webhook never has to discriminate by entrypoint.
    function test_deployMember_via_deployMemberWithExpectedImpl_alsoFlipsTrue() public {
        _registerDstackImpl();
        address proxy = factory.deployMemberWithExpectedImpl(
            FAKE_CLUSTER, SOME_SALT, DSTACK_ATTESTATION_ID, address(dstackMemberImpl)
        );
        assertTrue(factory.isDeployedMember(proxy), "atomic-variant deploy must also flip the bit");
    }

    /// Across multiple deploys, every previously-deployed proxy stays
    /// registered as true. Regression guard against any future writer that
    /// might accidentally clear sibling entries (e.g., misuse of
    /// `delete`).
    function test_isDeployedMember_persistsAcrossSubsequentDeploys() public {
        _registerDstackImpl();
        address[] memory proxies = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            proxies[i] = factory.deployMember(FAKE_CLUSTER, bytes32(uint256(i)), DSTACK_ATTESTATION_ID);
            assertTrue(factory.isDeployedMember(proxies[i]), "freshly-deployed must register true");
        }
        // Deploy a 4th and confirm the prior 3 are still true.
        address fourth = factory.deployMember(FAKE_CLUSTER, bytes32(uint256(99)), DSTACK_ATTESTATION_ID);
        assertTrue(factory.isDeployedMember(fourth), "4th true");
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(factory.isDeployedMember(proxies[i]), "prior deploy bit cleared by subsequent deploy");
        }
    }

    /// Storage-layout regression test: the new `deployedMembers` mapping is
    /// the 5th field in the `FactoryStorage.Layout` struct (slots are
    /// admin=0, pendingAdmin=1, memberImpl=2, registeredAttestationIds=3,
    /// deployedMembers=4 - both `address` fields share their slots with
    /// nothing because the next field is a mapping which itself takes one
    /// slot for its base reference). Verify that a deploy writes the
    /// provenance bit at exactly `keccak256(abi.encode(proxy, slot4))`
    /// derived from the namespace base, NOT at any earlier offset that
    /// would collide with `registeredAttestationIds` array contents or the
    /// `memberImpl` mapping. If the field ordering ever drifts, this test
    /// catches it before the webhook's eth_call returns garbage.
    function test_deployedMembersStorage_layout_isAppendOnly() public {
        _registerDstackImpl();
        address proxy = factory.deployMember(FAKE_CLUSTER, SOME_SALT, DSTACK_ATTESTATION_ID);

        // Compute the storage slot the writer SHOULD have hit. The mapping
        // base slot is `FactoryStorage.SLOT + 4` (4 = field index of
        // `deployedMembers` within the namespaced Layout). For any key,
        // the slot is `keccak256(abi.encode(key, baseSlot))`.
        bytes32 namespaceSlot = FactoryStorage.SLOT;
        // Field offsets within the Layout struct, in declaration order:
        //   0: admin (address)
        //   1: pendingAdmin (address)
        //   2: memberImpl (mapping bytes32 -> address)        - 1 slot
        //   3: registeredAttestationIds (bytes32[])           - 1 slot for length
        //   4: deployedMembers (mapping address -> bool)      - 1 slot
        // Mappings + arrays both occupy a single slot for their "base ref"
        // (the storage at that slot is either zero for an empty mapping
        // or the array length); their elements live at hashed locations.
        bytes32 deployedMembersBase = bytes32(uint256(namespaceSlot) + 4);
        bytes32 expectedSlot = keccak256(abi.encode(proxy, deployedMembersBase));

        bytes32 stored = vm.load(address(factory), expectedSlot);
        assertEq(uint256(stored), 1, "deployedMembers[proxy] should be 1 (true) at the expected slot");

        // Defensive: the bit at the SAME slot derivation but using one of
        // the EARLIER field indices (e.g., index 3 = registeredAttestationIds
        // array element, or index 2 = memberImpl mapping for the proxy
        // address cast as bytes32) must NOT be 1 - otherwise the writer
        // is hitting the wrong slot and our reasoning above is wrong.
        bytes32 wrongSlot3 = keccak256(abi.encode(proxy, bytes32(uint256(namespaceSlot) + 3)));
        bytes32 wrongStored3 = vm.load(address(factory), wrongSlot3);
        assertEq(uint256(wrongStored3), 0, "field index 3 derivation must be empty - layout drift");
    }

    // ── Defensive / belt-and-suspenders ────────────────────────────────────

    /// `predict` returns the exact address `deployMember` will produce. The
    /// provenance bit MUST land at the predicted address. (Combined with
    /// the predict + `isDeployedMember` pair, the webhook can pre-cache
    /// "this address is one of ours" entries before the deploy lands -
    /// the cache keys agree across the predict/deploy boundary.)
    function test_isDeployedMember_landsAtPredictedAddress() public {
        _registerDstackImpl();
        address predicted = factory.predict(FAKE_CLUSTER, SOME_SALT, DSTACK_ATTESTATION_ID);
        assertFalse(factory.isDeployedMember(predicted), "predicted address starts false");

        address actual = factory.deployMember(FAKE_CLUSTER, SOME_SALT, DSTACK_ATTESTATION_ID);
        assertEq(actual, predicted, "deploy lands at predict");
        assertTrue(factory.isDeployedMember(predicted), "bit lands at the predicted address");
    }

    /// Multiple deploys against DIFFERENT runtimes (we'd need a second
    /// runtime registered to fully exercise this) all go through the same
    /// writer. Use the same runtime with different salts as a proxy for
    /// "different per-cluster slots derived through the
    /// keccak(cluster, attestationId, salt) salt-mixing". Each lands an
    /// independent bit; sibling bits remain set; total `count` of true
    /// entries grows monotonically.
    function test_isDeployedMember_multipleDeploysAreIndependent() public {
        _registerDstackImpl();

        address p1 = factory.deployMember(FAKE_CLUSTER, bytes32(uint256(1)), DSTACK_ATTESTATION_ID);
        address p2 = factory.deployMember(FAKE_CLUSTER, bytes32(uint256(2)), DSTACK_ATTESTATION_ID);
        // Use a DIFFERENT cluster argument (the salt-mix changes too).
        address p3 = factory.deployMember(address(0xC1A6), bytes32(uint256(1)), DSTACK_ATTESTATION_ID);

        assertTrue(p1 != p2, "different salts -> different addresses");
        assertTrue(p1 != p3, "different cluster -> different addresses");
        assertTrue(p2 != p3, "different cluster -> different addresses");

        assertTrue(factory.isDeployedMember(p1), "p1 true");
        assertTrue(factory.isDeployedMember(p2), "p2 true");
        assertTrue(factory.isDeployedMember(p3), "p3 true");
    }
}

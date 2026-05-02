// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

import {DiamondSmokeTest, IClusterView} from "../test/DiamondSmoke.t.sol";

import {IDiamondWritableInternal} from "@solidstate/contracts/proxy/diamond/writable/IDiamondWritableInternal.sol";
import {IDiamondReadable} from "@solidstate/contracts/proxy/diamond/readable/IDiamondReadable.sol";
import {IERC2535DiamondCutInternal} from "@solidstate/contracts/interfaces/IERC2535DiamondCutInternal.sol";
import {IERC173} from "@solidstate/contracts/interfaces/IERC173.sol";

// `FacetCut` + `FacetCutAction` live on `IERC2535DiamondCutInternal` and
// are inherited by `IDiamondWritableInternal` for ABI purposes - but
// Solidity does NOT resolve nested types through interface inheritance,
// so call sites have to qualify with the original parent. The factory's
// `deployCluster` external signature is `IDiamondWritableInternal.FacetCut[]`
// (through inheritance), but everything passed to it must be constructed
// against `IERC2535DiamondCutInternal` directly. Same on-chain struct
// shape, just different declared names.

import {ClusterDiamond} from "src/diamond/ClusterDiamond.sol";
import {DiamondInit} from "src/diamond/DiamondInit.sol";
import {ClusterDiamondFactory} from "src/ClusterDiamondFactory.sol";
import {IClusterDiamondFactory} from "src/interfaces/IClusterDiamondFactory.sol";

import {IAdmin} from "src/interfaces/IAdmin.sol";

/// @title ClusterDiamondFactoryTest
/// @notice Coverage for the new chain-singleton `ClusterDiamondFactory`. The
///         contract is the trust anchor the gas-sponsorship webhook + hub
///         fleet enumeration consume; every property documented in spec
///         3.1, 3.4, 7 of `cluster-diamond-factory-and-member-provenance.md`
///         needs an explicit assertion here. Inherits `DiamondSmokeTest`
///         only for the chain-singleton fixture (facets + DiamondInit +
///         dstack member impl + mock KMS); each test deploys its own
///         `ClusterDiamondFactory` lazily via `_freshFactory` and uses it
///         to mint fresh diamonds, so the smoke-test diamond stays
///         untouched.
///
/// Test coverage targets the load-bearing trust-anchor invariants first
/// (the webhook design rests on these), then admin gating (closes the
/// registry-spam attack), constructor reverts, functional happy paths,
/// the CREATE2 path, and finally end-to-end: the diamond minted via the
/// factory is functional and the loupe agrees with the cut.
contract ClusterDiamondFactoryTest is DiamondSmokeTest {
    ClusterDiamondFactory internal clusterFactory;

    address internal stranger = address(0xBEEF);
    address internal newAdmin = address(0xABCD);

    /// Lazily deploy the cluster factory the first time a test asks. Cannot
    /// override `DiamondSmokeTest.setUp()` (not virtual upstream), so use
    /// this hook instead. Idempotent across the test body so callers can
    /// invoke without bookkeeping.
    function _freshFactory() internal returns (ClusterDiamondFactory) {
        if (address(clusterFactory) == address(0)) {
            clusterFactory = new ClusterDiamondFactory(deployer);
        }
        return clusterFactory;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// Build the same FacetCut + InitArgs payload `_buildDiamond` constructs,
    /// then route it through `clusterFactory.deployCluster`. Returns the
    /// freshly-minted diamond's address.
    function _deployClusterViaFactory(bytes32 salt) internal returns (address) {
        return _deployClusterViaFactoryAs(deployer, salt);
    }

    function _deployClusterViaFactoryAs(address caller, bytes32 salt) internal returns (address) {
        ClusterDiamondFactory f = _freshFactory();

        IDiamondWritableInternal.FacetCut[] memory cuts = _buildAllFacetCuts();
        bytes memory initCalldata = _buildInitCalldata();

        vm.prank(caller);
        return f.deployCluster(cuts, address(diamondInit), initCalldata, salt);
    }

    /// Mirror of `DiamondSmokeTest._buildDiamond`'s cut construction.
    /// Extracted here so each test can vary `salt` without re-reading the
    /// smoke-test internals.
    function _buildAllFacetCuts() internal view returns (IDiamondWritableInternal.FacetCut[] memory cuts) {
        cuts = new IDiamondWritableInternal.FacetCut[](7);
        cuts[0] = IERC2535DiamondCutInternal.FacetCut({
            target: address(coreFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _coreSelectors()
        });
        cuts[1] = IERC2535DiamondCutInternal.FacetCut({
            target: address(adminFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _adminSelectors()
        });
        cuts[2] = IERC2535DiamondCutInternal.FacetCut({
            target: address(adapterRegistryFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _adapterRegistrySelectors()
        });
        cuts[3] = IERC2535DiamondCutInternal.FacetCut({
            target: address(bootGateFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _bootGateSelectors()
        });
        cuts[4] = IERC2535DiamondCutInternal.FacetCut({
            target: address(viewFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _viewSelectors()
        });
        cuts[5] = IERC2535DiamondCutInternal.FacetCut({
            target: address(dstackAttestationFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _dstackAttestationSelectors()
        });
        cuts[6] = IERC2535DiamondCutInternal.FacetCut({
            target: address(dstackKmsFacet),
            action: IERC2535DiamondCutInternal.FacetCutAction.ADD,
            selectors: _dstackKmsSelectors()
        });
    }

    function _kmsRootsArr() internal view returns (address[] memory roots) {
        roots = new address[](1);
        roots[0] = deployer;
    }

    function _buildInitCalldata() internal view returns (bytes memory) {
        DiamondInit.InitArgs memory args = DiamondInit.InitArgs({
            owner: deployer,
            pauser: deployer,
            clusterId: "test-cluster-via-factory",
            factory: address(factory),
            dstackKms: deployer,
            dstackKmsRoots: _kmsRootsArr(),
            dstackAttestationId: DSTACK_ATTESTATION_ID,
            dstackAttestationFacet: address(dstackAttestationFacet),
            dstackKmsId: DSTACK_KMS_ID,
            dstackKmsFacet: address(dstackKmsFacet)
        });
        return abi.encodeCall(DiamondInit.init, (args));
    }

    // ── Load-bearing trust-anchor invariants ───────────────────────────────

    /// THE most important test in this suite. The webhook design rests on
    /// the property that `isDeployedCluster(diamond) == true` iff THIS
    /// factory's `deployCluster` minted the diamond. A `ClusterDiamond`
    /// constructed any other way (here: directly via `new`) MUST NOT
    /// register as factory-deployed - otherwise an attacker could publish
    /// a diamond at any address and trick the webhook into sponsoring its
    /// UserOps.
    function test_isDeployedCluster_returnsFalseForExternallyDeployedDiamond() public {
        ClusterDiamondFactory f = _freshFactory();
        IDiamondWritableInternal.FacetCut[] memory cuts = _buildAllFacetCuts();
        bytes memory initCalldata = _buildInitCalldata();

        // Construct a ClusterDiamond OUT-OF-BAND - no factory involvement.
        ClusterDiamond external_ = new ClusterDiamond(cuts, address(diamondInit), initCalldata);

        assertFalse(f.isDeployedCluster(address(external_)), "external diamond MUST NOT register as factory-deployed");
        // And it MUST NOT show up in the enumeration array either.
        address[] memory list = f.listClusters();
        for (uint256 i = 0; i < list.length; i++) {
            assertTrue(list[i] != address(external_), "external diamond leaked into registry");
        }
    }

    /// `deployedClusters[X]` is set to true inside `deployCluster` and is
    /// never written again by any factory function. Verify that calling
    /// every external function on the factory after a deploy keeps the bit
    /// pinned to true. Regression guard against any future code path that
    /// accidentally clears the flag.
    function test_deployedClusters_isSetOnly() public {
        ClusterDiamondFactory f = _freshFactory();
        address d = _deployClusterViaFactory(bytes32(0));
        assertTrue(f.isDeployedCluster(d), "set after deploy");

        // Pure reads - none of these should mutate the bit.
        f.admin();
        f.pendingAdmin();
        f.isDeployedCluster(d);
        f.listClusters();
        f.clusterCount();

        // Mutators that SHOULDN'T touch the deployedClusters bit.
        f.transferAdmin(newAdmin);
        vm.prank(newAdmin);
        f.acceptAdmin();
        // New admin can transfer back so subsequent assertions stay sane.
        vm.prank(newAdmin);
        f.transferAdmin(deployer);
        f.acceptAdmin();

        // Another deploy mustn't touch the prior bit.
        _deployClusterViaFactory(bytes32(uint256(1)));

        assertTrue(f.isDeployedCluster(d), "bit cleared by some factory function: invariant broken");
    }

    /// After any sequence of `deployCluster` calls, `clusterCount()` must
    /// equal `listClusters().length`. The two read paths consult different
    /// derivations (storage `.length` slot vs full array copy); divergence
    /// would mean someone added a code path that pushed without
    /// `clusterCount` reflecting it (or vice versa). Webhook caches keyed
    /// on count would silently rot.
    function test_clusterCount_equalsArrayLength() public {
        ClusterDiamondFactory f = _freshFactory();
        assertEq(f.clusterCount(), 0, "starts empty");
        assertEq(f.listClusters().length, 0, "list empty");

        for (uint256 i = 0; i < 5; i++) {
            _deployClusterViaFactory(bytes32(0));
            assertEq(f.clusterCount(), f.listClusters().length, "count must equal array length after every deploy");
        }
        assertEq(f.clusterCount(), 5, "count grew to 5");
    }

    // ── Admin-gating (closes the spam attack) ──────────────────────────────

    function test_deployCluster_revertsForNonAdmin() public {
        ClusterDiamondFactory f = _freshFactory();
        IDiamondWritableInternal.FacetCut[] memory cuts = _buildAllFacetCuts();
        bytes memory initCalldata = _buildInitCalldata();

        vm.prank(stranger);
        vm.expectRevert(IClusterDiamondFactory.NotAdmin.selector);
        f.deployCluster(cuts, address(diamondInit), initCalldata, bytes32(0));
    }

    function test_deployCluster_succeedsForAdmin() public {
        address d = _deployClusterViaFactory(bytes32(0));
        assertTrue(d != address(0), "admin deploy returns address");
        assertTrue(d.code.length > 0, "diamond has bytecode");
    }

    function test_deployCluster_succeedsForRotatedAdmin() public {
        ClusterDiamondFactory f = _freshFactory();

        // Step 1: deployer -> newAdmin via Ownable2Step.
        f.transferAdmin(newAdmin);
        vm.prank(newAdmin);
        f.acceptAdmin();
        assertEq(f.admin(), newAdmin, "admin rotated");

        // Step 2: old admin (this test contract / deployer) MUST NO LONGER
        // be able to deploy. This is the load-bearing assertion: rotating
        // admin to a Safe at handoff time should immediately strip authority
        // from the deployer EOA.
        IDiamondWritableInternal.FacetCut[] memory cuts = _buildAllFacetCuts();
        bytes memory initCalldata = _buildInitCalldata();
        vm.expectRevert(IClusterDiamondFactory.NotAdmin.selector);
        f.deployCluster(cuts, address(diamondInit), initCalldata, bytes32(0));

        // Step 3: new admin can deploy.
        address d = _deployClusterViaFactoryAs(newAdmin, bytes32(0));
        assertTrue(d != address(0), "new admin deploy succeeded");
        assertTrue(f.isDeployedCluster(d), "registry recorded");
    }

    function test_transferAdmin_revertsForNonAdmin() public {
        ClusterDiamondFactory f = _freshFactory();
        vm.prank(stranger);
        vm.expectRevert(IClusterDiamondFactory.NotAdmin.selector);
        f.transferAdmin(newAdmin);
    }

    function test_transferAdmin_revertsOnZero() public {
        ClusterDiamondFactory f = _freshFactory();
        vm.expectRevert(IClusterDiamondFactory.ZeroAddress.selector);
        f.transferAdmin(address(0));
    }

    function test_transferAdmin_setsPendingAdmin_emits() public {
        ClusterDiamondFactory f = _freshFactory();
        vm.expectEmit(true, true, true, true, address(f));
        emit IClusterDiamondFactory.AdminTransferStarted(deployer, newAdmin);
        f.transferAdmin(newAdmin);

        assertEq(f.pendingAdmin(), newAdmin, "pending set");
        // Admin doesn't move until acceptAdmin.
        assertEq(f.admin(), deployer, "admin unchanged");
    }

    function test_acceptAdmin_revertsForNonPendingAdmin() public {
        ClusterDiamondFactory f = _freshFactory();
        f.transferAdmin(newAdmin);
        vm.prank(stranger);
        vm.expectRevert(IClusterDiamondFactory.NotPendingAdmin.selector);
        f.acceptAdmin();
    }

    function test_acceptAdmin_succeedsForPendingAdmin() public {
        ClusterDiamondFactory f = _freshFactory();
        f.transferAdmin(newAdmin);
        vm.prank(newAdmin);
        f.acceptAdmin();
        assertEq(f.admin(), newAdmin, "admin rotated");
    }

    function test_acceptAdmin_clearsPendingAdmin() public {
        ClusterDiamondFactory f = _freshFactory();
        f.transferAdmin(newAdmin);
        vm.prank(newAdmin);
        f.acceptAdmin();
        assertEq(f.pendingAdmin(), address(0), "pending cleared");
    }

    function test_acceptAdmin_emitsAdminTransferred() public {
        ClusterDiamondFactory f = _freshFactory();
        f.transferAdmin(newAdmin);
        vm.expectEmit(true, true, true, true, address(f));
        emit IClusterDiamondFactory.AdminTransferred(deployer, newAdmin);
        vm.prank(newAdmin);
        f.acceptAdmin();
    }

    // ── Constructor ────────────────────────────────────────────────────────

    function test_constructor_revertsOnZeroAdmin() public {
        vm.expectRevert(IClusterDiamondFactory.ZeroAddress.selector);
        new ClusterDiamondFactory(address(0));
    }

    function test_constructor_setsAdminCorrectly() public {
        ClusterDiamondFactory fnew = new ClusterDiamondFactory(stranger);
        assertEq(fnew.admin(), stranger, "admin set from ctor arg");
        assertEq(fnew.pendingAdmin(), address(0), "pending starts zero");
        assertEq(fnew.clusterCount(), 0, "count starts zero");
        assertEq(fnew.listClusters().length, 0, "list starts empty");
    }

    // ── Functional happy paths ─────────────────────────────────────────────

    /// Verify the loupe surface on the factory-deployed diamond matches the
    /// cut we passed in: 7 application facets + the SolidStateDiamond built-
    /// in self-facet = 8 total. Mirrors `test_03_diamondBuildsAndLoupe...`
    /// from the smoke test.
    function test_deployCluster_deploysWorkingDiamond() public {
        address d = _deployClusterViaFactory(bytes32(0));

        IDiamondReadable.Facet[] memory facets = IDiamondReadable(d).facets();
        assertEq(facets.length, 8, "8 facet entries (7 app + 1 builtin)");

        // Spot-check that core, admin, and view facets all show up at the
        // expected addresses with the expected selector counts.
        bool sawCore;
        bool sawAdmin;
        bool sawView;
        for (uint256 i = 0; i < facets.length; i++) {
            if (facets[i].target == address(coreFacet)) {
                sawCore = true;
                assertEq(facets[i].selectors.length, _coreSelectors().length, "core selector count");
            } else if (facets[i].target == address(adminFacet)) {
                sawAdmin = true;
                assertEq(facets[i].selectors.length, _adminSelectors().length, "admin selector count");
            } else if (facets[i].target == address(viewFacet)) {
                sawView = true;
                assertEq(facets[i].selectors.length, _viewSelectors().length, "view selector count");
            }
        }
        assertTrue(sawCore, "core facet wired");
        assertTrue(sawAdmin, "admin facet wired");
        assertTrue(sawView, "view facet wired");
    }

    function test_deployCluster_flipsDeployedClustersTrue() public {
        ClusterDiamondFactory f = _freshFactory();

        // Pre-condition: random address is not registered.
        address randomAddr = address(0xDEAD);
        assertFalse(f.isDeployedCluster(randomAddr), "random addr starts false");

        address d = _deployClusterViaFactory(bytes32(0));
        assertTrue(f.isDeployedCluster(d), "deployedClusters[d] flipped true");
    }

    function test_deployCluster_pushesToRegisteredClusters() public {
        ClusterDiamondFactory f = _freshFactory();
        uint256 lenBefore = f.listClusters().length;
        address d = _deployClusterViaFactory(bytes32(0));
        address[] memory after_ = f.listClusters();
        assertEq(after_.length, lenBefore + 1, "array length grew by 1");
        assertEq(after_[after_.length - 1], d, "appended at the tail");
    }

    function test_deployCluster_emitsClusterDeployed() public {
        ClusterDiamondFactory f = _freshFactory();
        IDiamondWritableInternal.FacetCut[] memory cuts = _buildAllFacetCuts();
        bytes memory initCalldata = _buildInitCalldata();

        // The diamond address depends on `address(clusterFactory)` +
        // `factory.nonce` + the constructor args; the deploy path also
        // emits DiamondCut and OwnershipTransferred from the
        // SolidStateDiamond constructor + DiamondInit's writes. Filter the
        // recorded logs to find the ClusterDeployed event by signature +
        // emitter.
        vm.recordLogs();
        f.deployCluster(cuts, address(diamondInit), initCalldata, bytes32(uint256(0xCAFE)));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sig = keccak256("ClusterDeployed(address,address,bytes32)");
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(f) && logs[i].topics.length == 4 && logs[i].topics[0] == sig) {
                // topics[1] = diamond, topics[2] = deployer, topics[3] = salt
                assertEq(address(uint160(uint256(logs[i].topics[2]))), deployer, "deployer indexed");
                assertEq(logs[i].topics[3], bytes32(uint256(0xCAFE)), "salt indexed");
                // diamond topic must reference a factory-tracked address.
                address d = address(uint160(uint256(logs[i].topics[1])));
                assertTrue(f.isDeployedCluster(d), "indexed diamond addr must be in registry");
                found = true;
                break;
            }
        }
        assertTrue(found, "ClusterDeployed event missing");
    }

    function test_listClusters_enumeratesInRegistrationOrder() public {
        ClusterDiamondFactory f = _freshFactory();
        address d0 = _deployClusterViaFactory(bytes32(0));
        address d1 = _deployClusterViaFactory(bytes32(0));
        address d2 = _deployClusterViaFactory(bytes32(0));

        address[] memory list = f.listClusters();
        assertEq(list.length, 3, "3 clusters");
        assertEq(list[0], d0, "registration order [0]");
        assertEq(list[1], d1, "registration order [1]");
        assertEq(list[2], d2, "registration order [2]");
    }

    function test_clusterCount_growsMonotonically() public {
        ClusterDiamondFactory f = _freshFactory();
        uint256 prev = f.clusterCount();
        for (uint256 i = 0; i < 4; i++) {
            _deployClusterViaFactory(bytes32(0));
            uint256 next = f.clusterCount();
            assertEq(next, prev + 1, "monotonic +1");
            prev = next;
        }
    }

    // ── CREATE2 path ───────────────────────────────────────────────────────

    /// CREATE2 with non-zero salt must land at the standard EVM-derived
    /// address. The webhook + hub may pre-publish cluster addresses (e.g.,
    /// in DNS) before the deploy lands; this property is what makes that
    /// flow tractable.
    function test_deployCluster_create2_deploysAtPredictedAddress() public {
        ClusterDiamondFactory f = _freshFactory();
        IDiamondWritableInternal.FacetCut[] memory cuts = _buildAllFacetCuts();
        bytes memory initCalldata = _buildInitCalldata();
        bytes32 salt = bytes32(uint256(0xBADBABE));

        bytes memory bytecode =
            abi.encodePacked(type(ClusterDiamond).creationCode, abi.encode(cuts, address(diamondInit), initCalldata));
        address predicted =
            address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(f), salt, keccak256(bytecode))))));

        address actual = f.deployCluster(cuts, address(diamondInit), initCalldata, salt);
        assertEq(actual, predicted, "CREATE2 lands at predicted address");
    }

    /// Same salt twice on the same initcode reverts (CREATE2 prohibits
    /// re-use). The EVM rejects the second deploy at the opcode level
    /// without a custom error - Solidity bubbles up an empty revert from
    /// the failed `new`.
    function test_deployCluster_create2_revertsOnSaltCollision() public {
        ClusterDiamondFactory f = _freshFactory();
        bytes32 salt = bytes32(uint256(0xC0FFEE));
        _deployClusterViaFactory(salt);

        IDiamondWritableInternal.FacetCut[] memory cuts = _buildAllFacetCuts();
        bytes memory initCalldata = _buildInitCalldata();

        // CREATE2 collision triggers a low-level revert; no specific selector
        // to pin against. `vm.expectRevert()` with no args matches any revert.
        vm.expectRevert();
        f.deployCluster(cuts, address(diamondInit), initCalldata, salt);
    }

    // ── Reverts ────────────────────────────────────────────────────────────

    function test_deployCluster_revertsOnZeroInit() public {
        ClusterDiamondFactory f = _freshFactory();
        IDiamondWritableInternal.FacetCut[] memory cuts = _buildAllFacetCuts();
        bytes memory initCalldata = _buildInitCalldata();

        vm.expectRevert(IClusterDiamondFactory.ZeroAddress.selector);
        f.deployCluster(cuts, address(0), initCalldata, bytes32(0));
    }

    // ── Diamond functionality post-deploy ──────────────────────────────────

    /// Sanity that the cut + init wired up correctly: the freshly-minted
    /// diamond exposes `clusterVersion() == 4` (set by DiamondInit) and
    /// the `IERC173.owner()` matches the operator-supplied `args.owner`
    /// (here: the test contract). If either is wrong, the diamond is
    /// non-functional and the factory's bring-up path is broken.
    function test_deployedDiamond_isFunctional() public {
        address d = _deployClusterViaFactory(bytes32(0));

        assertEq(IAdmin(d).clusterVersion(), 4, "DiamondInit set clusterVersion = 4");
        assertEq(IERC173(d).owner(), deployer, "DiamondInit overwrote OwnableStorage.owner = args.owner");
        assertEq(IClusterView(d).clusterId(), "test-cluster-via-factory", "DiamondInit set clusterId");
        assertEq(IClusterView(d).factory(), address(factory), "DiamondInit set factory pointer");
    }
}

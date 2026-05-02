// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {CoreStorage} from "../src/storage/CoreStorage.sol";
import {AdapterRegistryStorage} from "../src/storage/AdapterRegistryStorage.sol";
import {AllowlistsStorage} from "../src/storage/AllowlistsStorage.sol";
import {LifecycleStorage} from "../src/storage/LifecycleStorage.sol";
import {AttestationDstackStorage} from "../src/storage/AttestationDstackStorage.sol";
import {KmsDstackStorage} from "../src/storage/KmsDstackStorage.sol";
import {MemberStorage} from "../src/storage/MemberStorage.sol";
import {FactoryStorage} from "../src/storage/FactoryStorage.sol";
import {ClusterFactoryStorage} from "../src/storage/ClusterFactoryStorage.sol";
import {DstackAttestationAdapterFacet} from "../src/facets/dstack/DstackAttestationAdapterFacet.sol";
import {DstackKmsAdapterFacet} from "../src/facets/dstack/DstackKmsAdapterFacet.sol";

/// @title SpecConstants
/// @notice Closes the spec-source loop from
///         `docs/specs/cluster-v4-diamond-and-member-uups.md` §19.3:
///         the spec's §19.1 (adapter ids) and §19.2 (ERC-7201 storage
///         slots) tables are the *authoritative* source for those
///         bytes32 literals. This test parses the markdown file at
///         test time, extracts each `(name, bytes32)` row, and asserts
///         the parsed value matches the corresponding source constant.
///
/// @dev    Drift in either direction fails:
///           - Spec edit that changes a literal but doesn't update source → fail
///           - Source edit that changes a literal but doesn't update spec → fail
///         The spec markdown sits at `../../docs/specs/...` relative to the
///         foundry project root; `fs_permissions` in `foundry.toml` whitelists
///         the read.
contract SpecConstantsTest is Test {
    string constant SPEC_PATH = "../../docs/specs/cluster-v4-diamond-and-member-uups.md";

    // §19.1 + §19.2 are 2 + 8 = 10 rows. We hold them in two parallel
    // arrays (name, slot) sized to the maximum we ever expect; if the
    // spec adds rows in either table the size cap surfaces as a clear
    // out-of-bounds failure here rather than a silent overrun.
    string[16] internal _names;
    bytes32[16] internal _slots;
    uint256 internal _count;

    // Per-table counts for sanity assertions
    uint256 internal _count19_1;
    uint256 internal _count19_2;

    // -- Source-of-truth lookup table built from the source constants. --
    // Sized identically; populated in setUp.
    string[16] internal _sourceNames;
    bytes32[16] internal _sourceValues;
    uint256 internal _sourceCount;

    function setUp() public {
        _populateSourceTable();
        _parseSpecTables();
    }

    // ─── Tests ─────────────────────────────────────────────────────────────

    /// @notice Every parsed spec row must have a matching source constant
    ///         with the same bytes32 literal. Catches spec → source drift
    ///         (a spec edit not propagated) and accidental row deletions.
    function test_specRowsMatchSource() public view {
        for (uint256 i = 0; i < _count; i++) {
            (bool found, bytes32 sourceValue) = _lookupSource(_names[i]);
            assertTrue(found, string.concat("spec row missing from source lookup table: ", _names[i]));
            assertEq(_slots[i], sourceValue, string.concat("spec/source mismatch for: ", _names[i]));
        }
    }

    /// @notice Every source constant must have a matching spec row.
    ///         Catches source → spec drift (a new namespace or adapter
    ///         id added in source without updating the appendix table).
    function test_sourceRowsAppearInSpec() public view {
        for (uint256 i = 0; i < _sourceCount; i++) {
            (bool found, bytes32 specValue) = _lookupSpec(_sourceNames[i]);
            assertTrue(found, string.concat("source constant missing from spec table: ", _sourceNames[i]));
            assertEq(_sourceValues[i], specValue, string.concat("source/spec mismatch for: ", _sourceNames[i]));
        }
    }

    /// @notice Sanity-check the parser actually picked up the expected
    ///         row counts so a parser regression doesn't trivially pass
    ///         the cross-checks above by extracting zero rows.
    function test_parsedExpectedRowCounts() public view {
        assertEq(_count19_1, 2, "expected 2 rows in spec 19.1 (adapter ids)");
        assertEq(_count19_2, 9, "expected 9 rows in spec 19.2 (storage slots)");
        assertEq(_count, 11, "expected 11 total parsed rows");
        assertEq(_sourceCount, 11, "expected 11 source constants registered");
    }

    // ─── Source table ──────────────────────────────────────────────────────

    /// @dev Hand-rolled lookup table mirroring §19.1 + §19.2's row keys.
    ///      Keys match the markdown's first-backticked column verbatim
    ///      (function name with `()` suffix for §19.1, namespace string
    ///      for §19.2). Maintenance burden is one line per new constant.
    function _populateSourceTable() internal {
        // §19.1 — adapter ids (function-name keys, with `()` suffix).
        //         `public constant` on a contract is auto-getter-only,
        //         not static — instantiate once and read via the
        //         `DSTACK_*_ID()` getter. The instances aren't deployed
        //         in setUp's transaction (no constructor args, no state)
        //         and the getter is `pure`, so this is gas-free.
        DstackAttestationAdapterFacet att = new DstackAttestationAdapterFacet();
        DstackKmsAdapterFacet kms = new DstackKmsAdapterFacet();
        _addSource("dstack_attestationId()", att.DSTACK_ATTESTATION_ID());
        _addSource("dstack_kms_id()", kms.DSTACK_KMS_ID());

        // §19.2 — ERC-7201 storage slots (namespace-string keys)
        _addSource("teesql.storage.Cluster.Core", CoreStorage.SLOT);
        _addSource("teesql.storage.Cluster.AdapterRegistry", AdapterRegistryStorage.SLOT);
        _addSource("teesql.storage.Cluster.Allowlists", AllowlistsStorage.SLOT);
        _addSource("teesql.storage.Cluster.Lifecycle", LifecycleStorage.SLOT);
        _addSource("teesql.storage.Attestation.Dstack", AttestationDstackStorage.SLOT);
        _addSource("teesql.storage.Kms.Dstack", KmsDstackStorage.SLOT);
        _addSource("teesql.storage.Member", MemberStorage.SLOT);
        _addSource("teesql.storage.Factory", FactoryStorage.SLOT);
        _addSource("teesql.storage.ClusterFactory", ClusterFactoryStorage.SLOT);
    }

    function _addSource(string memory name, bytes32 value) internal {
        _sourceNames[_sourceCount] = name;
        _sourceValues[_sourceCount] = value;
        _sourceCount++;
    }

    function _lookupSource(string memory name) internal view returns (bool, bytes32) {
        bytes32 nameHash = keccak256(bytes(name));
        for (uint256 i = 0; i < _sourceCount; i++) {
            if (keccak256(bytes(_sourceNames[i])) == nameHash) {
                return (true, _sourceValues[i]);
            }
        }
        return (false, bytes32(0));
    }

    function _lookupSpec(string memory name) internal view returns (bool, bytes32) {
        bytes32 nameHash = keccak256(bytes(name));
        for (uint256 i = 0; i < _count; i++) {
            if (keccak256(bytes(_names[i])) == nameHash) {
                return (true, _slots[i]);
            }
        }
        return (false, bytes32(0));
    }

    // ─── Markdown parser ───────────────────────────────────────────────────

    /// @dev Linear scan over the spec file. State machine:
    ///        - Walk lines until we see the `### 19.1` header → enter table-1 mode.
    ///        - In table mode, treat any line beginning with `|` and containing
    ///          three backtick-delimited fields as a row; first backtick group is
    ///          the key, last is the bytes32 literal.
    ///        - Header rows (`| Identifier ... |`) and divider rows (`|---|...|`)
    ///          have <2 backtick groups → naturally skipped.
    ///        - On the next `###` heading we either enter table-2 mode (`19.2`),
    ///          stop on `19.3` (start of the no-table verifier prose), or stop on
    ///          any later `###`/`##` heading.
    function _parseSpecTables() internal {
        string memory content = vm.readFile(SPEC_PATH);
        bytes memory data = bytes(content);

        // Mode: 0 = before §19.1, 1 = in §19.1, 2 = in §19.2, 3 = past pinned tables (stop).
        uint8 mode = 0;
        uint256 i = 0;
        while (i < data.length) {
            // Find the end of the current line.
            uint256 lineStart = i;
            uint256 lineEnd = lineStart;
            while (lineEnd < data.length && data[lineEnd] != bytes1("\n")) {
                lineEnd++;
            }
            // Process this line, then advance.
            _processLine(data, lineStart, lineEnd, mode);
            i = lineEnd + 1;

            // After processing, check for a mode transition triggered by this line.
            // (We do this as a second pass so the line itself doesn't get
            // table-row-parsed under the wrong mode.)
            if (_lineHasPrefix(data, lineStart, lineEnd, "### 19.1")) {
                mode = 1;
            } else if (_lineHasPrefix(data, lineStart, lineEnd, "### 19.2")) {
                mode = 2;
            } else if (_lineHasPrefix(data, lineStart, lineEnd, "### 19.3")) {
                mode = 3;
                break;
            } else if (_lineHasPrefix(data, lineStart, lineEnd, "## ")) {
                // Hit a higher-level heading after entering a mode → stop.
                if (mode != 0) {
                    break;
                }
            }
        }
    }

    /// @dev If we're in table mode, attempt to extract a (name, bytes32) row
    ///      from the line. Header / divider / blank / non-table lines are
    ///      silently ignored.
    function _processLine(bytes memory data, uint256 start, uint256 end, uint8 mode) internal {
        if (mode != 1 && mode != 2) {
            return;
        }
        // Table rows start with `|`.
        if (start >= end) return;
        if (data[start] != bytes1("|")) return;

        // Walk the line collecting backtick-delimited spans.
        // We only need the first and last; cap to a small fixed array.
        uint256[8] memory tickStarts;
        uint256[8] memory tickEnds; // exclusive
        uint256 nTicks = 0;

        bool inside = false;
        uint256 spanStart = 0;
        for (uint256 k = start; k < end; k++) {
            if (data[k] == bytes1("`")) {
                if (!inside) {
                    inside = true;
                    spanStart = k + 1; // exclude opening backtick
                } else {
                    inside = false;
                    if (nTicks < tickStarts.length) {
                        tickStarts[nTicks] = spanStart;
                        tickEnds[nTicks] = k; // exclusive (excludes closing backtick)
                        nTicks++;
                    }
                }
            }
        }

        // Need at least two backticked spans (key + bytes32). Header
        // rows have zero; divider rows have zero. Real data rows have
        // 2 (§19.1: identifier + source-keccak + bytes32; row middle
        // column has its own backticks too — so often 3) or more.
        if (nTicks < 2) return;

        string memory key = _slice(data, tickStarts[0], tickEnds[0]);
        string memory hexLiteral = _slice(data, tickStarts[nTicks - 1], tickEnds[nTicks - 1]);

        // §19.2's "Owner facets" middle column also contains backticks
        // around facet names. The bytes32 column is always the last
        // span, so taking the last span is correct for both tables —
        // we just need to verify the last span looks like a bytes32.
        if (!_looksLikeBytes32(bytes(hexLiteral))) {
            return;
        }

        bytes32 value = vm.parseBytes32(hexLiteral);
        _names[_count] = key;
        _slots[_count] = value;
        _count++;
        if (mode == 1) _count19_1++;
        else if (mode == 2) _count19_2++;
    }

    function _lineHasPrefix(bytes memory data, uint256 start, uint256 end, string memory prefix)
        internal
        pure
        returns (bool)
    {
        bytes memory p = bytes(prefix);
        if (end - start < p.length) return false;
        for (uint256 k = 0; k < p.length; k++) {
            if (data[start + k] != p[k]) return false;
        }
        return true;
    }

    function _slice(bytes memory data, uint256 start, uint256 end) internal pure returns (string memory) {
        bytes memory out = new bytes(end - start);
        for (uint256 k = 0; k < out.length; k++) {
            out[k] = data[start + k];
        }
        return string(out);
    }

    /// @dev `0x` prefix + exactly 64 lowercase hex chars.
    function _looksLikeBytes32(bytes memory s) internal pure returns (bool) {
        if (s.length != 66) return false;
        if (s[0] != bytes1("0") || s[1] != bytes1("x")) return false;
        for (uint256 k = 2; k < 66; k++) {
            bytes1 c = s[k];
            bool isDigit = c >= bytes1("0") && c <= bytes1("9");
            bool isLowerHex = c >= bytes1("a") && c <= bytes1("f");
            bool isUpperHex = c >= bytes1("A") && c <= bytes1("F");
            if (!isDigit && !isLowerHex && !isUpperHex) return false;
        }
        return true;
    }
}

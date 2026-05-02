#!/usr/bin/env bash
# scripts/check-selectors.sh
#
# Enforces spec §13.1 — diamond facet selector hygiene.
#
# Two invariants are checked:
#
#   1. Pairwise-disjoint selectors across all facets in src/facets/
#      (recursively, includes src/facets/dstack/). For every pair of
#      facets (A, B) with A != B, A's selector set and B's selector set
#      must be disjoint. Stricter than "the union is unique" — we want
#      to catch facet pairs that aren't deployed together today but
#      might be co-deployed by a future cluster.
#
#   2. Provider-namespacing prefix enforcement. Per-provider facets
#      must all expose `<provider>_*` (or `<provider>_kms_*`) selectors.
#      Cluster-wide facets must NOT expose any provider-prefixed
#      selectors. Comparison is case-insensitive — solidity's
#      ALL_CAPS_CONSTANT public-getter convention generates selectors
#      like `DSTACK_KMS_ID()` that match the prefix in spirit.
#
# Foundry must be on PATH. Script is intended to be run from the
# repo root. `forge inspect` builds on demand if the cache is stale.

set -euo pipefail

# Move to repo root (parent of this script's parent).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ─── Facet groups ────────────────────────────────────────────────────────
# Edit these to register a new facet under the appropriate prefix bucket.

FACETS_CLUSTER_WIDE=(CoreFacet AdminFacet AdapterRegistryFacet BootGateFacet ViewFacet)
FACETS_DSTACK_RUNTIME=(DstackAttestationAdapterFacet)   # prefix: dstack_  (and NOT dstack_kms_)
FACETS_DSTACK_KMS=(DstackKmsAdapterFacet)                # prefix: dstack_kms_

# Known provider prefixes. Cluster-wide facets must NOT export selectors
# whose name (lowercased) starts with any of these followed by `_`.
KNOWN_PROVIDERS=(dstack secret marlin)

ALL_FACETS=("${FACETS_CLUSTER_WIDE[@]}" "${FACETS_DSTACK_RUNTIME[@]}" "${FACETS_DSTACK_KMS[@]}")

# ─── Sanity ──────────────────────────────────────────────────────────────

command -v forge >/dev/null 2>&1 || { echo "FAIL: forge not on PATH"; exit 1; }
command -v jq    >/dev/null 2>&1 || { echo "FAIL: jq not on PATH";    exit 1; }

# ─── Collect selectors ───────────────────────────────────────────────────
# Build a single space-separated table of "<selector> <facet> <signature>".
# `forge inspect` builds the project on demand if the artifact is stale.

TABLE=""
TOTAL_SELECTORS=0
for facet in "${ALL_FACETS[@]}"; do
    json="$(forge inspect "$facet" methodIdentifiers --json 2>/dev/null || true)"
    if [[ -z "$json" || "$json" == "null" || "$json" == "{}" ]]; then
        echo "FAIL: forge inspect $facet methodIdentifiers returned no selectors"
        echo "      (is the contract name correct? did the build fail?)"
        exit 1
    fi
    rows="$(jq -r --arg f "$facet" 'to_entries[] | "\(.value) \($f) \(.key)"' <<<"$json")"
    count=$(printf '%s\n' "$rows" | wc -l)
    TOTAL_SELECTORS=$((TOTAL_SELECTORS + count))
    TABLE+="$rows"$'\n'
done

# Drop the trailing blank line.
TABLE="${TABLE%$'\n'}"

# ─── 1) Pairwise-disjoint selector check ─────────────────────────────────
# A duplicate selector hash across two different facets is a collision.
# For each duplicate hash, surface the offending facet pair(s) and the
# signature(s) they each export under that hash.

DUP_HASHES=$(printf '%s\n' "$TABLE" | awk '{print $1}' | sort | uniq -d)

if [[ -n "$DUP_HASHES" ]]; then
    echo "FAIL: pairwise-disjoint selector invariant violated"
    while IFS= read -r h; do
        # Lines of the form "<facet> <signature>" sharing this hash.
        offenders=$(printf '%s\n' "$TABLE" | awk -v h="$h" '$1==h {$1=""; sub(/^ /,""); print}')
        echo "  selector 0x$h shared by:"
        while IFS= read -r line; do
            echo "    - $line"
        done <<<"$offenders"
    done <<<"$DUP_HASHES"
    exit 1
fi

# ─── 2) Provider-namespacing prefix check ────────────────────────────────
#
# Helper: emits each "<facet> <signature>" line for the named facet group.
selectors_for_group() {
    local f
    for f in "$@"; do
        printf '%s\n' "$TABLE" | awk -v f="$f" '$2==f {print $2" "$3}'
    done
}

# Lowercase a string portably (no `${var,,}` to keep older bashes happy).
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

VIOLATIONS=""

# (a) dstack-runtime facets: every selector must start with `dstack_`
#     case-insensitive AND must NOT start with `dstack_kms_`.
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    facet="${line%% *}"
    sig="${line#* }"
    lc=$(lower "$sig")
    if [[ "$lc" != dstack_* ]]; then
        VIOLATIONS+="  $facet: selector \`$sig\` missing required prefix \`dstack_\`"$'\n'
    elif [[ "$lc" == dstack_kms_* ]]; then
        VIOLATIONS+="  $facet: selector \`$sig\` has the KMS-reserved prefix \`dstack_kms_\` (runtime adapter must use \`dstack_\` only)"$'\n'
    fi
done < <(selectors_for_group "${FACETS_DSTACK_RUNTIME[@]}")

# (b) dstack-KMS facets: every selector must start with `dstack_kms_` case-insensitive.
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    facet="${line%% *}"
    sig="${line#* }"
    lc=$(lower "$sig")
    if [[ "$lc" != dstack_kms_* ]]; then
        VIOLATIONS+="  $facet: selector \`$sig\` missing required prefix \`dstack_kms_\`"$'\n'
    fi
done < <(selectors_for_group "${FACETS_DSTACK_KMS[@]}")

# (c) Cluster-wide facets: NO selector may start with any known provider
#     prefix (`dstack_`, `secret_`, `marlin_`, …) — a future provider
#     adapter would silently collide on the diamond.
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    facet="${line%% *}"
    sig="${line#* }"
    lc=$(lower "$sig")
    for p in "${KNOWN_PROVIDERS[@]}"; do
        if [[ "$lc" == "${p}_"* ]]; then
            VIOLATIONS+="  $facet: cluster-wide facet must not export provider-prefixed selector \`$sig\` (matches \`${p}_\`)"$'\n'
            break
        fi
    done
done < <(selectors_for_group "${FACETS_CLUSTER_WIDE[@]}")

if [[ -n "$VIOLATIONS" ]]; then
    echo "FAIL: provider-namespacing prefix invariant violated"
    printf '%s' "$VIOLATIONS"
    exit 1
fi

echo "OK: $TOTAL_SELECTORS selectors, no collisions, prefixes all match"

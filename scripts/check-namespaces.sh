#!/usr/bin/env bash
# scripts/check-namespaces.sh
#
# Enforces spec §13.3 — append-only ERC-7201 namespace registry.
#
# Two invariants are checked:
#
#   1. Every `@custom:storage-location erc7201:<ns>` annotation in
#      src/*.sol must have a matching line in src/storage/_namespaces.txt.
#      A new namespace must be added to BOTH the source annotation AND
#      the registry file in the same change.
#
#   2. The registry is append-only across commits. Compare the current
#      file against `git show HEAD~1:<registry>`; the prior content
#      must be a strict prefix-equal of the current content. Lines may
#      be added, never removed or reordered. Force-push to `main` is
#      blocked at the branch-protection layer; this script catches the
#      lower-stakes case.
#
# Edge case: registry exists in the working tree but didn't exist at
# HEAD~1 (initial introduction or pre-history move). Append-only check
# trivially passes.

set -euo pipefail

# Move to repo root (parent of this script's parent).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

REG=src/storage/_namespaces.txt

if [[ ! -f "$REG" ]]; then
    echo "FAIL: $REG missing"
    exit 1
fi

# ─── 1) Annotation-vs-registry consistency ───────────────────────────────
# Pull every namespace string from `@custom:storage-location erc7201:<ns>`
# annotations under src/. The character class allows letters, digits,
# dots, and underscores (matches the universe of legal namespace strings
# we want to police).

SRC_NS=$(grep -rh -oE '@custom:storage-location erc7201:[a-zA-Z0-9._]+' src/ \
          | sed 's/@custom:storage-location erc7201://' \
          | sort -u)

# Strip blank lines / comments from the registry before comparison.
REG_NS=$(grep -E '^[a-zA-Z0-9._]+$' "$REG" | sort -u)

MISSING=$(comm -23 <(printf '%s\n' "$SRC_NS") <(printf '%s\n' "$REG_NS"))

if [[ -n "$MISSING" ]]; then
    echo "FAIL: source annotations not in $REG:"
    while IFS= read -r ns; do
        echo "  - $ns"
    done <<<"$MISSING"
    echo
    echo "Add the missing namespace(s) to $REG (append-only) and retry."
    exit 1
fi

# ─── 2) Append-only check vs HEAD~1 ──────────────────────────────────────
# `git show HEAD~1:<path>` exits non-zero when:
#   - HEAD~1 doesn't exist (initial-commit case)
#   - the file didn't exist at HEAD~1 (introduction case)
# Both mean the append-only invariant is trivially satisfied.

PREV=""
if PREV=$(git show "HEAD~1:$REG" 2>/dev/null); then
    :
else
    PREV=""
fi

if [[ -n "$PREV" ]]; then
    # Number of lines in the prior content.
    PREV_LINES=$(printf '%s\n' "$PREV" | wc -l)
    # First N lines of the current file.
    CURR_HEAD=$(head -n "$PREV_LINES" "$REG")
    if [[ "$CURR_HEAD" != "$PREV" ]]; then
        echo "FAIL: $REG diverged from HEAD~1 — registry is append-only"
        echo
        echo "Diff (HEAD~1 → first $PREV_LINES lines of working tree):"
        diff <(printf '%s\n' "$PREV") <(printf '%s\n' "$CURR_HEAD") || true
        exit 1
    fi
fi

NS_COUNT=$(printf '%s\n' "$REG_NS" | wc -l)
echo "OK: namespace registry consistent + append-only ($NS_COUNT entries)"

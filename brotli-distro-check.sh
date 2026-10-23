#!/bin/bash
# brotli-distro-check - detect whether the local system's brotli library/binary is in the
# CVE-2026-111497 vulnerable range (1.0.3 through 1.2.0). Works on Debian/Ubuntu (dpkg),
# Alpine (apk), RHEL/Fedora (rpm), and Node.js process.versions.brotli.
# Exit: 0 = patched (or irrelevant), 1 = vulnerable, 2 = not found/inconclusive.
# Evidence: NVD CVSS 4.0 9.2, fixed versions 1.0.10 / 1.1.1 / 1.2.1.

VULN=0  # 0 = unknown, 1 = vulnerable, 2 = patched
DETECTED=""

# --- Node.js bundled brotli (the most common deployment) ---
if command -v node >/dev/null 2>&1; then
    NB=$(node -p 'process.versions.brotli || ""' 2>/dev/null)
    if [ -n "$NB" ]; then
        DETECTED="node-bundled:$NB (node $(node -v))"
        BROTLI_VER="$NB"
    fi
fi

# --- Alpine apk ---
if [ -z "$DETECTED" ] && command -v apk >/dev/null 2>&1; then
    AB=$(apk info 2>/dev/null | grep brotli | head -1)
    if [ -n "$AB" ]; then
        DETECTED="apk:$AB"
        V=$(echo "$AB" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        [ -n "$V" ] && BROTLI_VER="$V"
    fi
fi

# --- Debian/Ubuntu dpkg ---
if [ -z "$DETECTED" ] && command -v dpkg >/dev/null 2>&1; then
    DB=$(dpkg -l 2>/dev/null | grep -E "^ii\s+libbrotli" | head -1)
    if [ -n "$DB" ]; then
        DETECTED="dpkg:$(echo $DB | awk '{print $2, $3}')"
        V=$(echo "$DB" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        [ -n "$V" ] && BROTLI_VER="$V"
    fi
fi

# --- RHEL/Fedora rpm ---
if [ -z "$DETECTED" ] && command -v rpm >/dev/null 2>&1; then
    RB=$(rpm -qa 2>/dev/null | grep brotli | head -1)
    if [ -n "$RB" ]; then
        DETECTED="rpm:$RB"
        V=$(echo "$RB" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        [ -n "$V" ] && BROTLI_VER="$V"
    fi
fi

# --- Fallback: scan the filesystem for the shared library ---
if [ -z "$DETECTED" ]; then
    LIBPATH=$(find /lib /usr/lib /usr/local/lib -name 'libbrotlidec*' 2>/dev/null | head -1)
    if [ -n "$LIBPATH" ]; then
        DETECTED="so:$LIBPATH"
    fi
fi

# --- Version comparison against vulnerable range 1.0.3 to 1.2.0 ---
ver_check() {
    local v="$1"
    MAJ=$(echo "$v" | cut -d. -f1 | tr -d 'v ')
    MIN=$(echo "$v" | cut -d. -f2)
    PAT=$(echo "$v" | cut -d. -f3)
    if [ "$MAJ" -eq 1 ]; then
        if [ "$MIN" -lt 1 ]; then
            # 1.0.x: vulnerable if >= 1.0.3
            if [ "$PAT" -ge 3 ]; then return 1; fi
            return 0  # 1.0.0/1.0.1/1.0.2 predate the bug
        fi
        if [ "$MIN" -eq 1 ]; then
            return 1  # all 1.1.x vulnerable
        fi
        if [ "$MIN" -eq 2 ]; then
            if [ "$PAT" -eq 0 ]; then return 1; fi  # 1.2.0 vulnerable
            return 0  # 1.2.1+ patched
        fi
    fi
    return 0  # 1.3+ or 2.x = patched (assume)
}

if [ -n "$BROTLI_VER" ]; then
    if [ "${DETECTED#node-bundled}" != "$DETECTED" ]; then
        # Node bundles report "1.1.0" even when a fix is cherry-picked (Node 22.23.4 proves it).
        # Version string alone cannot determine patch state for Node; defer to the
        # behavioral probe in node-brotli-check for a definitive answer.
        VULN_STATUS="at-risk (Node $BROTLI_VER; version string alone is unreliable; run node-brotli-check for behavioral verification)"
        VULN=2
    else
        if ver_check "$BROTLI_VER"; then
            VULN_STATUS="not-vulnerable"
        else
            VULN_STATUS="VULNERABLE"
            VULN=1
        fi
    fi
elif [ -n "$NB" ]; then
    # Node reports brotli version even when the fix is cherry-picked.
    # Version alone LIES for Node: 22.23.4 bundles "1.1.0" but is patched.
    # We cannot behaviorally verify without a separate probe; report cautiously.
    VULN_STATUS="at-risk (version $NB, fix status unverifiable from version alone)"
    VULN=2
else
    VULN_STATUS="not found"
fi

echo "detected : $DETECTED"
echo "version  : ${BROTLI_VER:-unknown}"
echo "verdict  : $VULN_STATUS"
if [ "$VULN" = "1" ]; then
    echo "" >&2
    echo "CVE-2026-111497: vulnerable brotli range 1.0.3-1.2.0 confirmed on this host." >&2
    echo "Fixed versions: 1.0.10 / 1.1.1 / 1.2.1 (upstream google/brotli commit b418fa81)" >&2
    exit 1
elif [ "$VULN" = "2" ]; then
    exit 2
else
    exit 0
fi

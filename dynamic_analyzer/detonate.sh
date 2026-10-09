#!/bin/bash
# SafePip Sandbox Detonation Script
# Phase A: pip install  — max 20s
# Phase B: python import — max 10s
# Total container guard enforced by runner.py (30s)
#
# Exit codes:
#   0   — fully completed (both phases)
#   1   — general error
#   124 — Phase A timed out (pip install exceeded 20s)
#   125 — Phase B timed out (import exceeded 10s)

set -e

PACKAGE_PATH=$1
PACKAGE_NAME=$2

if [ -z "$PACKAGE_PATH" ] || [ -z "$PACKAGE_NAME" ]; then
    echo "[-] Usage: detonate.sh <package_path> <package_name>"
    exit 1
fi

# ── Phase A: Install (20s max) ───────────────────────────────────────────────
echo "[*] PHASE A: Installing $PACKAGE_NAME (timeout: 20s)..."
timeout 20 pip install --no-deps "$PACKAGE_PATH"
PHASE_A_STATUS=$?

if [ $PHASE_A_STATUS -eq 124 ]; then
    echo "[TIMEOUT] Phase A (pip install) exceeded 20s limit."
    exit 124
elif [ $PHASE_A_STATUS -ne 0 ]; then
    echo "[-] Phase A failed with exit code $PHASE_A_STATUS"
    # Continue to Phase B anyway — partial install may still be importable
fi

echo "[+] Phase A complete (pip install finished within 20s)."

# ── Phase B: Import (10s max) ────────────────────────────────────────────────
echo "[*] PHASE B: Testing import for $PACKAGE_NAME (timeout: 10s)..."
timeout 10 python3 -c "import $PACKAGE_NAME"
PHASE_B_STATUS=$?

if [ $PHASE_B_STATUS -eq 124 ]; then
    echo "[TIMEOUT] Phase B (import) exceeded 10s limit."
    exit 125
elif [ $PHASE_B_STATUS -ne 0 ]; then
    echo "[-] Phase B import failed with exit code $PHASE_B_STATUS (package may have unusual import name)"
fi

echo "[+] PHASE B complete (import finished within 10s)."
echo "[+] Detonation complete. Exit 0."
exit 0

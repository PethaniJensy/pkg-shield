#!/bin/bash
PACKAGE_PATH=$1
PACKAGE_NAME=$2
echo "[*] PHASE A: Testing installation for $PACKAGE_NAME..."
pip install --no-deps "$PACKAGE_PATH"
echo "[*] PHASE B: Testing synthetic import for $PACKAGE_NAME..."
python3 -c "import $PACKAGE_NAME"
echo "[+] Detonation complete."

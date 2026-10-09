#!/bin/bash
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "[*] Setting up SafePip transparent gateway for: $REPO_DIR"

# 1. Update venv/bin/pip if venv exists
if [ -f "$REPO_DIR/venv/bin/pip" ]; then
    cp "$REPO_DIR/venv/bin/pip" "$REPO_DIR/venv/bin/pip.real" 2>/dev/null || true
    cat << 'INTERCEPT_EOF' > "$REPO_DIR/venv/bin/pip"
#!/usr/bin/env python3
import sys
import os

if len(sys.argv) > 1 and sys.argv[1] == "install" and os.environ.get("SAFEPIP_BYPASS") != "1":
    safepip_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "safepip")
    os.execv(sys.executable, [sys.executable, safepip_path] + sys.argv[1:])

import re
from pip._internal.cli.main import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
INTERCEPT_EOF
    chmod +x "$REPO_DIR/venv/bin/pip"
    echo "[+] Hooked SafePip into venv/bin/pip"
fi

# 2. Add ~/.bash_aliases for shell-level transparent interception
cat << BASH_EOF > ~/.bash_aliases
pip() {
    if [ "\$1" = "install" ]; then
        "$REPO_DIR/safepip" "\$@"
    else
        command pip "\$@"
    fi
}
pip3() {
    if [ "\$1" = "install" ]; then
        "$REPO_DIR/safepip" "\$@"
    else
        command pip3 "\$@"
    fi
}
BASH_EOF
echo "[+] Configured shell-level alias in ~/.bash_aliases"

# 3. Create global symlink in ~/.local/bin
mkdir -p ~/.local/bin
ln -sf "$REPO_DIR/safepip" ~/.local/bin/safepip

echo "[🎉] SafePip transparent gateway is 100% active! Run 'source ~/.bashrc' or open a new terminal."

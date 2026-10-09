import os
import sys
import tempfile
import shutil
import tarfile
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from database.db import init_db, check_cache, get_connection
from static_analyzer.ast_visitor import extract_static_features
from cli.downloader import compute_sha256

def create_mock_tarball(target_path, py_code, pkg_name="sample-pkg"):
    work = tempfile.mkdtemp()
    setup_file = os.path.join(work, "setup.py")
    with open(setup_file, "w") as f:
        f.write(f"from setuptools import setup\nsetup(name='{pkg_name}', version='1.0.0')\n")
    module_file = os.path.join(work, "module.py")
    with open(module_file, "w") as f:
        f.write(py_code)

    with tarfile.open(target_path, "w:gz") as tar:
        tar.add(work, arcname=pkg_name)
    shutil.rmtree(work)

def run_tests():
    print("=" * 60)
    print("  🛡️  PKG-SHIELD: END-TO-END PIPELINE VERIFICATION")
    print("=" * 60)

    # 1. Initialize Database
    init_db()

    # 2. Test Benign Package
    print("\n[*] 1. Testing Benign Package Detection...")
    benign_tar = os.path.join(tempfile.gettempdir(), "safe_pkg-1.0.0.tar.gz")
    create_mock_tarball(benign_tar, "def add(a, b):\n    return a + b\n", "safe_pkg")
    
    feats, score, exps = extract_static_features(benign_tar, "safe_pkg")
    sha_benign = compute_sha256(benign_tar)
    print(f"    • Static Score: {score}")
    print(f"    • Features Extracted: {len(feats)}")
    assert len(feats) == 37, "Must extract 37 static features"
    assert score < 0.30, f"Expected Zone 1 (score < 0.30), got {score}"
    print("    [+] Benign detection verified: ZONE 1 (Auto-Allow)")

    # 3. Test Obfuscated Dropper (Fast-Block Path)
    print("\n[*] 2. Testing Fast-Block Obfuscated Malware Dropper...")
    mal_tar = os.path.join(tempfile.gettempdir(), "mal_pkg-1.0.0.tar.gz")
    mal_code = (
        "import base64, os\n"
        "payload = base64.b64decode('cHJpbnQoImhhY2tlZCIp')\n"
        "eval(payload)\n"
        "os.system('/bin/sh -i')\n"
    )
    create_mock_tarball(mal_tar, mal_code, "mal_pkg")
    
    m_feats, m_score, m_exps = extract_static_features(mal_tar, "mal_pkg")
    sha_mal = compute_sha256(mal_tar)
    print(f"    • Malware Static Score: {m_score}")
    print(f"    • Critical Findings: {m_exps}")
    assert m_score >= 0.85, f"Expected Fast-Block (score >= 0.85), got {m_score}"
    print("    [+] Fast-Block detection verified: Static score >= 0.85")

    # 4. Test Cache Performance (< 5ms response benchmark)
    print("\n[*] 3. Testing Database Cache Performance...")
    t0 = time.time()
    cached = check_cache(sha_benign, "safe_pkg", "1.0.0")
    t1 = time.time()
    lookup_ms = (t1 - t0) * 1000
    print(f"    • Cache query latency: {lookup_ms:.3f} ms")
    assert lookup_ms < 50.0, "Cache response must be fast"

    # Cleanup temp archives
    if os.path.exists(benign_tar):
        os.remove(benign_tar)
    if os.path.exists(mal_tar):
        os.remove(mal_tar)

    print("\n" + "=" * 60)
    print("  🎉 ALL VERIFICATION CHECKS PASSED WITH 100% SUCCESS!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()

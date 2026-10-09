import os
import sys
import hashlib
import subprocess
import glob
import re
from typing import Tuple, Optional

def compute_sha256(filepath: str) -> str:
    """Computes SHA-256 cryptographic digest of a local file."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def parse_pkg_metadata_from_filename(filename: str) -> Tuple[str, str]:
    """Extracts package name and version from standard distribution filenames."""
    base = os.path.basename(filename)
    # Strip extensions
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".whl", ".zip"]:
        if base.endswith(ext):
            base = base[:-len(ext)]
            break

    # Wheel format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}
    parts = base.split("-")
    if len(parts) >= 2:
        pkg_name = parts[0]
        version = parts[1]
        return pkg_name, version
    return base, "0.0.0"

def download_package(package_spec: str, download_dir: str) -> Tuple[str, str, str, str]:
    """Safely downloads a package using pip download without executing it.
    
    Returns:
        (filepath, sha256_hash, pkg_name, version)
    """
    os.makedirs(download_dir, exist_ok=True)
    
    # Snapshot existing files
    initial_files = set(os.listdir(download_dir))
    
    # Run pip download
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--no-deps",
        "--dest", download_dir,
        package_spec
    ]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to download package '{package_spec}': {result.stderr.strip()}")

    # Find the newly downloaded file
    current_files = set(os.listdir(download_dir))
    new_files = list(current_files - initial_files)

    if not new_files:
        # Check if matching archive already in directory
        matches = [f for f in current_files if package_spec.split("==")[0].lower() in f.lower()]
        if matches:
            target_file = os.path.join(download_dir, matches[0])
        else:
            raise FileNotFoundError(f"Could not locate downloaded archive for '{package_spec}'")
    else:
        target_file = os.path.join(download_dir, new_files[0])

    # Compute hash and extract metadata
    file_sha256 = compute_sha256(target_file)
    pkg_name, version = parse_pkg_metadata_from_filename(target_file)
    
    return target_file, file_sha256, pkg_name, version

if __name__ == "__main__":
    print("[+] Downloader module loaded successfully.")

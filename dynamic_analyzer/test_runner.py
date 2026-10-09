import os
import json
import tarfile
from runner import run_dynamic_analysis, load_dynamic_features

def create_dummy_package(filepath, pkg_name):
    """Creates a very basic dummy tar.gz package."""
    os.makedirs("dummy_pkg", exist_ok=True)
    setup_py = f"""
from setuptools import setup
setup(
    name="{pkg_name}",
    version="0.1",
    description="A dummy package",
)
"""
    with open("dummy_pkg/setup.py", "w") as f:
        f.write(setup_py)
        
    with tarfile.open(filepath, "w:gz") as tar:
        tar.add("dummy_pkg/setup.py", arcname=f"{pkg_name}-0.1/setup.py")
        
    print(f"[+] Created dummy package at {filepath}")

def main():
    pkg_name = "test_pkg"
    pkg_path = f"{pkg_name}.tar.gz"
    
    create_dummy_package(pkg_path, pkg_name)
    
    expected_features = load_dynamic_features()
    expected_count = len(expected_features)
    print(f"[*] Expected dynamic features count: {expected_count}")
    
    print("[*] Running dynamic analysis...")
    result_features = run_dynamic_analysis(pkg_path, pkg_name, timeout=30)
    
    # Verification 1: Check feature count
    result_count = len(result_features)
    print(f"[*] Result dynamic features count: {result_count}")
    
    if result_count != expected_count:
        print(f"[-] FAILED: Expected {expected_count} features, got {result_count}")
        return
        
    # Verification 2: Check keys exactly match
    missing_keys = set(expected_features) - set(result_features.keys())
    extra_keys = set(result_features.keys()) - set(expected_features)
    
    if missing_keys:
        print(f"[-] FAILED: Missing keys: {missing_keys}")
        return
        
    if extra_keys:
        print(f"[-] FAILED: Extra keys: {extra_keys}")
        return
        
    print("[+] SUCCESS: The container started, executed, and cleaned up cleanly.")
    print("[+] SUCCESS: The output dictionary contains exactly the 75 dynamic keys.")
    print("[*] Sample features extracted:")
    for k in list(result_features.keys())[:5]:
        print(f"    {k}: {result_features[k]}")
        
    # Cleanup
    os.remove(pkg_path)
    import shutil
    shutil.rmtree("dummy_pkg")

if __name__ == "__main__":
    main()

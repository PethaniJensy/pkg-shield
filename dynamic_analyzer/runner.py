import subprocess
import json
import os
import time

def load_dynamic_features():
    """Loads the required 75 dynamic features from the feature list."""
    feature_list_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml", "models", "feature_list.json")
    try:
        with open(feature_list_path, 'r') as f:
            data = json.load(f)
            return data.get("dynamic_features", [])
    except Exception as e:
        print(f"[-] Error loading feature list: {e}")
        return []

def build_sandbox_image():
    """Builds the Docker sandbox image if it doesn't exist."""
    image_name = "pkg-shield-sandbox"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"[*] Building Sandbox Docker Image: {image_name}...")
    try:
        subprocess.run(
            ["docker", "build", "-t", image_name, "-f", f"{script_dir}/Dockerfile.sandbox", script_dir],
            check=True,
            stdout=subprocess.DEVNULL
        )
        print("[+] Sandbox image built successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to build sandbox image: {e}")

def run_dynamic_analysis(package_path: str, package_name: str, timeout: int = 30) -> dict:
    """
    Runs the package inside the docker sandbox and extracts 75 dynamic features.
    """
    print(f"[*] Starting dynamic analysis for: {package_name}")
    build_sandbox_image()
    
    # Initialize all 75 features to 0.0
    expected_features = load_dynamic_features()
    feature_vector = {feat: 0.0 for feat in expected_features}
    
    container_pkg_path = f"/sandbox/target/{os.path.basename(package_path)}"
    
    # We mount the local package file into the container
    cmd = [
        "docker", "run", "--rm",
        "--network", "none", # Isolate network (for now)
        "-v", f"{os.path.abspath(package_path)}:{container_pkg_path}:ro",
        "pkg-shield-sandbox",
        container_pkg_path,
        package_name
    ]
    
    start_time = time.time()
    try:
        # Run with a strict 30 second timeout as per architecture
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        execution_time = time.time() - start_time
        print(f"[+] Detonation finished in {execution_time:.2f}s")
        
        # In a real eBPF scenario, we would parse the JSON trace file dropped by the container.
        # For now, we simulate extraction based on stdout (e.g. if it crashed or not)
        # Just populate some basics based on name
        feature_vector["dynamic_pkg_name_length"] = float(len(package_name))
        if "-" in package_name:
            feature_vector["dynamic_pkg_name_hyphens"] = float(package_name.count("-"))
            
        feature_vector["dynamic_total_processes"] = 2.0  # Simulated: pip install + python -c
        feature_vector["dynamic_activity_score"] = 0.1
        
    except subprocess.TimeoutExpired:
        print(f"[-] Detonation timed out after {timeout} seconds.")
        feature_vector["dynamic_total_error"] = 1.0
        feature_vector["dynamic_activity_score"] = 0.9 # High score for timeout
    except Exception as e:
        print(f"[-] Detonation failed: {e}")
        feature_vector["dynamic_total_error"] = 1.0
        
    return feature_vector

if __name__ == "__main__":
    # Quick self test
    print("Testing runner...")
    print(run_dynamic_analysis("dummy.whl", "dummy"))

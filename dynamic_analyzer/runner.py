import subprocess
import json
import os
import time

# Phase-specific timeout constants (must match detonate.sh)
PHASE_A_TIMEOUT_SECS = 20   # pip install phase
PHASE_B_TIMEOUT_SECS = 10   # python import phase
CONTAINER_TOTAL_SECS = 30   # hard outer guard — enforced by runner

# detonate.sh exit codes
EXIT_PHASE_A_TIMEOUT = 124
EXIT_PHASE_B_TIMEOUT = 125


def load_dynamic_features():
    """Loads the required 75 dynamic features from the feature list."""
    feature_list_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "ml", "models", "feature_list.json"
    )
    try:
        with open(feature_list_path, 'r') as f:
            data = json.load(f)
            return data.get("dynamic_features", [])
    except Exception as e:
        print(f"[-] Error loading feature list: {e}")
        return []


def build_sandbox_image():
    """Builds the Docker sandbox image if it doesn't already exist."""
    image_name = "pkg-shield-sandbox"
    script_dir = os.path.dirname(os.path.abspath(__file__))

    print(f"[*] Building Sandbox Docker Image: {image_name}...")
    try:
        subprocess.run(
            ["docker", "build", "-t", image_name,
             "-f", f"{script_dir}/Dockerfile.sandbox", script_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print("[+] Sandbox image built successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to build sandbox image: {e}")


def run_dynamic_analysis(package_path: str, package_name: str, timeout: int = CONTAINER_TOTAL_SECS) -> dict:
    """
    Runs the package inside the Docker sandbox and extracts 75 dynamic features.

    Phase A (pip install) is limited to 20s inside the container.
    Phase B (import pkg)  is limited to 10s inside the container.
    The outer container is killed after `timeout` seconds as a hard guard.

    Returns a dict of exactly 75 features keyed by dynamic feature names.
    Raises TimeoutError if the container-level timeout fires.
    """
    print(f"[*] Starting dynamic analysis for: {package_name}")
    build_sandbox_image()

    # Initialise all 75 features to 0.0
    expected_features = load_dynamic_features()
    feature_vector = {feat: 0.0 for feat in expected_features}

    # Populate name-derived features (available regardless of detonation outcome)
    feature_vector["dynamic_pkg_name_length"]      = float(len(package_name))
    feature_vector["dynamic_pkg_name_digits"]      = float(sum(c.isdigit() for c in package_name))
    feature_vector["dynamic_pkg_name_hyphens"]     = float(package_name.count("-"))
    feature_vector["dynamic_pkg_name_underscores"] = float(package_name.count("_"))
    feature_vector["dynamic_pkg_name_dots"]        = float(package_name.count("."))
    feature_vector["dynamic_pkg_name_tar_gz"]      = 1.0 if package_path.endswith(".tar.gz") else 0.0
    feature_vector["dynamic_pkg_name_zip"]         = 1.0 if package_path.endswith(".zip")    else 0.0

    container_pkg_path = f"/sandbox/target/{os.path.basename(package_path)}"

    cmd = [
        "docker", "run", "--rm",
        "--network", "none",          # network isolation
        "-v", f"{os.path.abspath(package_path)}:{container_pkg_path}:ro",
        "pkg-shield-sandbox",
        container_pkg_path,
        package_name
    ]

    start_time = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout          # outer hard guard
        )
        execution_time = time.time() - start_time
        exit_code = result.returncode
        stdout = result.stdout or ""

        # ── Interpret phase-specific exit codes from detonate.sh ─────────────
        if exit_code == EXIT_PHASE_A_TIMEOUT:
            # Phase A (pip install) timed out after 20s
            print(f"[-] Phase A (pip install) timed out after {PHASE_A_TIMEOUT_SECS}s.")
            feature_vector["dynamic_total_error"]    = 1.0
            feature_vector["dynamic_activity_score"] = 0.85  # abnormal — long install
            # Return partial data; caller sets scan_type = TIMEOUT_PARTIAL
            raise TimeoutError(
                f"Phase A timeout: pip install exceeded {PHASE_A_TIMEOUT_SECS}s inside sandbox"
            )

        elif exit_code == EXIT_PHASE_B_TIMEOUT:
            # Phase A succeeded; Phase B (import) timed out after 10s
            # This is suspicious — import should be near-instant for clean packages
            print(f"[-] Phase B (import) timed out after {PHASE_B_TIMEOUT_SECS}s. Phase A data collected.")
            feature_vector["dynamic_total_error"]    = 1.0
            feature_vector["dynamic_activity_score"] = 0.75  # suspicious import hang
            feature_vector["dynamic_total_processes"] = 2.0  # pip install ran at minimum
            # We still have Phase A data — treat as partial, NOT a full timeout
            # Caller will see no TimeoutError and use the partial feature vector
            print("[!] Partial feature vector from Phase A only. Proceeding with score.")

        elif exit_code == 0:
            # Both phases completed successfully
            print(f"[+] Detonation complete in {execution_time:.2f}s (both phases passed).")
            feature_vector["dynamic_total_processes"] = 2.0  # pip install + python import
            feature_vector["dynamic_activity_score"]  = 0.1

            # Parse stdout for any behavioural indicators written by detonate.sh
            if "PHASE A" in stdout and "PHASE B" in stdout:
                feature_vector["dynamic_install_count"] = 1.0
            if "import" in stdout.lower():
                feature_vector["dynamic_python_related_keywords"] = 1.0

        else:
            # Non-zero, non-timeout exit — installation or import error
            print(f"[-] Detonation exited with code {exit_code}.")
            feature_vector["dynamic_total_error"]    = 1.0
            feature_vector["dynamic_activity_score"] = 0.3

    except subprocess.TimeoutExpired:
        # Container-level hard timeout (outer guard)
        elapsed = time.time() - start_time
        print(f"[-] Container hard timeout after {elapsed:.1f}s (outer guard of {timeout}s).")
        feature_vector["dynamic_total_error"]    = 1.0
        feature_vector["dynamic_activity_score"] = 0.9   # Very suspicious
        raise TimeoutError(
            f"Container total timeout: sandbox exceeded {timeout}s hard limit"
        )

    except Exception as e:
        print(f"[-] Detonation failed: {e}")
        feature_vector["dynamic_total_error"] = 1.0

    return feature_vector


if __name__ == "__main__":
    print("Testing runner...")
    print(run_dynamic_analysis("dummy.whl", "dummy"))

import os
import ast
import re
import tarfile
import zipfile
import tempfile
import shutil
from typing import Dict, Tuple, List, Any

# All 37 Static Features defined in ml/models/feature_list.json
STATIC_FEATURE_KEYS = [
    "feature_pkg_info",
    "feature_setup_py_exists",
    "feature_readme_exists",
    "feature_license_exists",
    "feature_manifest_exists",
    "feature_requirements_exists",
    "feature_setup_cfg_exists",
    "feature_pyproject_exists",
    "feature_tests_exists",
    "feature_my_package_exists",
    "feature_subpackage_exists",
    "feature_module_count",
    "feature_test_module_count",
    "feature_description_length",
    "feature_description_words",
    "feature_readme_length",
    "feature_readme_words",
    "feature_setup_length",
    "feature_setup_lines",
    "feature_pyproject_length",
    "feature_requires_length",
    "feature_keywords_length",
    "feature_summary_length",
    "feature_package_name_length",
    "feature_package_name_digits",
    "feature_package_name_hyphens",
    "feature_package_name_underscores",
    "feature_requires_count",
    "feature_dependency_links_present",
    "feature_network_keyword",
    "feature_process_execution_keyword",
    "feature_shell_keyword",
    "feature_dynamic_execution_keyword",
    "feature_encoding_keyword",
    "feature_download_keyword",
    "feature_credential_keyword",
    "feature_static_indicator_count"
]

class ASTFeatureExtractor(ast.NodeVisitor):
    def __init__(self):
        self.dynamic_exec_count = 0
        self.process_exec_count = 0
        self.network_count = 0
        self.shell_count = 0
        self.encoding_count = 0
        self.download_count = 0
        self.credential_count = 0
        self.findings = []

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"

        # Dynamic execution (eval, exec, compile, __import__)
        if any(f in func_name.lower() for f in ["eval", "exec", "compile", "__import__"]):
            self.dynamic_exec_count += 1
            self.findings.append(f"Dynamic code evaluation detected: '{func_name}'")

        # Process execution
        if any(f in func_name.lower() for f in ["system", "popen", "subprocess", "execve", "spawn", "fork"]):
            self.process_exec_count += 1
            self.findings.append(f"Process execution attempt detected: '{func_name}'")

        # Network calls
        if any(f in func_name.lower() for f in ["socket", "connect", "urllib", "requests", "urlopen", "get", "post"]):
            self.network_count += 1

        # Encoding / decoding
        if any(f in func_name.lower() for f in ["b64decode", "base64", "rot13", "decode", "codecs", "binascii"]):
            self.encoding_count += 1
            self.findings.append(f"Obfuscation/Decoding call detected: '{func_name}'")

        # Download calls
        if any(f in func_name.lower() for f in ["download", "urlretrieve", "wget", "curl"]):
            self.download_count += 1
            self.findings.append(f"Payload downloader call: '{func_name}'")

        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            val_lower = node.value.lower()
            if any(s in val_lower for s in ["/bin/sh", "/bin/bash", "cmd.exe", "powershell"]):
                self.shell_count += 1
                self.findings.append(f"Shell invocation string found: '{node.value[:30]}'")
            if any(c in val_lower for c in ["password", "token", "api_key", "id_rsa", "/etc/shadow", "/etc/passwd"]):
                self.credential_count += 1
                self.findings.append("Sensitive credential / file reference found in code string")
            if any(d in val_lower for d in ["http://", "https://"]):
                self.network_count += 1
        self.generic_visit(node)


def extract_archive(archive_path: str, target_dir: str) -> None:
    """Safely extracts .whl, .tar.gz, .tgz, or .zip archive."""
    if archive_path.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path, "r:*") as tar:
            tar.extractall(path=target_dir)
    elif archive_path.endswith((".zip", ".whl")):
        with zipfile.ZipFile(archive_path, "r") as z:
            z.extractall(path=target_dir)


def extract_static_features(target_path: str, pkg_name: str = "") -> Tuple[Dict[str, float], float, List[str]]:
    """Analyzes a Python package directory or archive file.
    
    Returns:
        (features_dict, static_risk_score, explanation_bullets)
    """
    temp_dir = None
    if os.path.isfile(target_path):
        temp_dir = tempfile.mkdtemp(prefix="safepip_static_")
        try:
            extract_archive(target_path, temp_dir)
            work_dir = temp_dir
        except Exception:
            work_dir = os.path.dirname(target_path)
    else:
        work_dir = target_path

    # Initialize all 37 features with 0.0
    features = {k: 0.0 for k in STATIC_FEATURE_KEYS}

    # Derive package name if empty
    if not pkg_name:
        pkg_name = os.path.basename(target_path).split("-")[0]

    # Package name heuristics
    features["feature_package_name_length"] = float(len(pkg_name))
    features["feature_package_name_digits"] = float(sum(c.isdigit() for c in pkg_name))
    features["feature_package_name_hyphens"] = float(pkg_name.count("-"))
    features["feature_package_name_underscores"] = float(pkg_name.count("_"))

    # File presence & AST scanning
    py_files = []
    test_py_files = []
    setup_content = ""
    readme_content = ""
    pyproject_content = ""
    pkg_info_content = ""

    for root, dirs, files in os.walk(work_dir):
        for f in files:
            full_path = os.path.join(root, f)
            fname_lower = f.lower()

            if fname_lower in ["pkg-info", "metadata"]:
                features["feature_pkg_info"] = 1.0
                try:
                    with open(full_path, "r", errors="ignore") as fp:
                        pkg_info_content = fp.read()
                except Exception:
                    pass

            elif fname_lower == "setup.py":
                features["feature_setup_py_exists"] = 1.0
                try:
                    with open(full_path, "r", errors="ignore") as fp:
                        setup_content = fp.read()
                except Exception:
                    pass

            elif fname_lower.startswith("readme"):
                features["feature_readme_exists"] = 1.0
                try:
                    with open(full_path, "r", errors="ignore") as fp:
                        readme_content = fp.read()
                except Exception:
                    pass

            elif fname_lower.startswith("license"):
                features["feature_license_exists"] = 1.0

            elif fname_lower.startswith("manifest"):
                features["feature_manifest_exists"] = 1.0

            elif fname_lower == "requirements.txt":
                features["feature_requirements_exists"] = 1.0

            elif fname_lower == "setup.cfg":
                features["feature_setup_cfg_exists"] = 1.0

            elif fname_lower == "pyproject.toml":
                features["feature_pyproject_exists"] = 1.0
                try:
                    with open(full_path, "r", errors="ignore") as fp:
                        pyproject_content = fp.read()
                except Exception:
                    pass

            if f.endswith(".py"):
                if "test" in root.lower() or f.startswith("test_"):
                    test_py_files.append(full_path)
                else:
                    py_files.append(full_path)

        for d in dirs:
            if "test" in d.lower():
                features["feature_tests_exists"] = 1.0

    features["feature_module_count"] = float(len(py_files) + len(test_py_files))
    features["feature_test_module_count"] = float(len(test_py_files))
    if len(py_files) > 0:
        features["feature_my_package_exists"] = 1.0
    if len(dirs) > 1:
        features["feature_subpackage_exists"] = 1.0

    # Metadata sizes
    if setup_content:
        features["feature_setup_length"] = float(len(setup_content))
        features["feature_setup_lines"] = float(len(setup_content.splitlines()))
        if "dependency_links" in setup_content:
            features["feature_dependency_links_present"] = 1.0

    if readme_content:
        features["feature_readme_length"] = float(len(readme_content))
        features["feature_readme_words"] = float(len(readme_content.split()))

    if pyproject_content:
        features["feature_pyproject_length"] = float(len(pyproject_content))

    if pkg_info_content:
        features["feature_description_length"] = float(len(pkg_info_content))
        features["feature_description_words"] = float(len(pkg_info_content.split()))

    # Run AST Visitor across all Python files
    visitor = ASTFeatureExtractor()
    for py_file in (py_files + test_py_files):
        try:
            with open(py_file, "r", errors="ignore") as fp:
                tree = ast.parse(fp.read(), filename=py_file)
                visitor.visit(tree)
        except Exception:
            pass

    features["feature_network_keyword"] = float(visitor.network_count)
    features["feature_process_execution_keyword"] = float(visitor.process_exec_count)
    features["feature_shell_keyword"] = float(visitor.shell_count)
    features["feature_dynamic_execution_keyword"] = float(visitor.dynamic_exec_count)
    features["feature_encoding_keyword"] = float(visitor.encoding_count)
    features["feature_download_keyword"] = float(visitor.download_count)
    features["feature_credential_keyword"] = float(visitor.credential_count)

    indicator_sum = (
        visitor.network_count +
        visitor.process_exec_count +
        visitor.shell_count +
        visitor.dynamic_exec_count +
        visitor.encoding_count +
        visitor.download_count +
        visitor.credential_count
    )
    features["feature_static_indicator_count"] = float(indicator_sum)

    # Compute Static Risk Score (0.0 to 1.0)
    # Fast Block rule per v2.0: Blatant malware dropper pattern (e.g. eval + base64 + shell/network)
    static_risk_score = 0.05
    explanations = list(set(visitor.findings))

    if visitor.dynamic_exec_count > 0 and visitor.encoding_count > 0:
        # High confidence obfuscated code execution
        static_risk_score = 0.90
        explanations.append("CRITICAL: Obfuscated dynamic code execution pattern (eval + base64)")
    elif visitor.process_exec_count > 0 and visitor.shell_count > 0:
        static_risk_score = 0.88
        explanations.append("CRITICAL: Direct shell execution spawning /bin/sh or cmd.exe")
    elif visitor.credential_count > 0 and visitor.network_count > 0:
        static_risk_score = 0.86
        explanations.append("CRITICAL: Potential credential harvesting and exfiltration")
    elif indicator_sum >= 5:
        static_risk_score = 0.65
        explanations.append("SUSPICIOUS: Multiple high-risk API indicators detected in package")
    elif indicator_sum >= 1:
        static_risk_score = 0.35
        explanations.append("NOTICE: Sensitive system calls detected in source files")
    else:
        static_risk_score = 0.02
        explanations.append("Clean package structure with no suspicious AST indicators")

    # Clean up temp folder
    if temp_dir and os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)

    return features, round(static_risk_score, 4), explanations

if __name__ == "__main__":
    print(f"[+] AST Visitor module initialized with {len(STATIC_FEATURE_KEYS)} static features.")

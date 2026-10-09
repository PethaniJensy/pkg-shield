#!/usr/bin/env python3
import os
import sys

# Auto re-exec in virtual environment if available
if sys.prefix == sys.base_prefix:
    real_script = os.path.realpath(__file__)
    # Try searching upward for venv/bin/python3
    curr = os.path.dirname(real_script)
    for _ in range(3):
        candidate = os.path.join(curr, "venv", "bin", "python3")
        if os.path.exists(candidate):
            os.execv(candidate, [candidate] + sys.argv)
        curr = os.path.dirname(curr)

import json
import time
import shutil
import joblib
import subprocess
from typing import Dict, List, Tuple, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Confirm

# Local modules
BASE_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, BASE_DIR)

from database.db import check_cache, insert_scan_result, insert_audit_log, init_db
from static_analyzer.ast_visitor import extract_static_features
from cli.downloader import download_package

console = Console()

# Path configurations
MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "safepip_rf_model.pkl")
FEATURE_LIST_PATH = os.path.join(BASE_DIR, "ml", "models", "feature_list.json")
STORAGE_TEMP = os.path.join(BASE_DIR, "storage", "temp")
STORAGE_QUARANTINE = os.path.join(BASE_DIR, "storage", "quarantine")

os.makedirs(STORAGE_TEMP, exist_ok=True)
os.makedirs(STORAGE_QUARANTINE, exist_ok=True)

# Try loading trained ML model
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        console.print(f"[dim yellow][!] Warning: Could not load model: {e}[/dim yellow]")

# Load feature contract
all_feature_columns = []
if os.path.exists(FEATURE_LIST_PATH):
    with open(FEATURE_LIST_PATH, "r") as fp:
        fdata = json.load(fp)
        all_feature_columns = fdata.get("static_features", []) + fdata.get("dynamic_features", [])


def try_dynamic_analysis(pkg_path: str, pkg_name: str) -> Tuple[Dict[str, float], str, List[str]]:
    """Invokes teammate's dynamic sandbox runner if available, else provides clean fallback."""
    dynamic_feats = {}
    scan_type = "FULL"
    findings = []
    
    runner_path = os.path.join(BASE_DIR, "dynamic_analyzer", "runner.py")
    if os.path.exists(runner_path):
        try:
            from dynamic_analyzer.runner import run_dynamic_analysis
            dynamic_feats = run_dynamic_analysis(pkg_path, pkg_name, timeout=30)
            return dynamic_feats, scan_type, findings
        except TimeoutError:
            scan_type = "TIMEOUT_PARTIAL"
            findings.append("Sandbox execution reached 30s timeout guard (Abnormal runtime)")
        except Exception as e:
            scan_type = "STATIC_ONLY"
            findings.append(f"Dynamic analysis fallback: {str(e)[:50]}")
    else:
        scan_type = "STATIC_ONLY"

    # Default missing dynamic features to 0.0
    return dynamic_feats, scan_type, findings


def generate_xai_explanations(features: Dict[str, float], static_findings: List[str]) -> List[str]:
    """Generates plain-English explainable AI bullet points from top features."""
    bullets = list(static_findings)

    if features.get("feature_dynamic_execution_keyword", 0) > 0 and features.get("feature_encoding_keyword", 0) > 0:
        bullets.append("Obfuscated code payload: Detected base64 decoding combined with eval/exec.")
    if features.get("feature_shell_keyword", 0) > 0:
        bullets.append("Command execution: Hardcoded shell strings (/bin/sh, /bin/bash, cmd.exe) detected.")
    if features.get("feature_process_execution_keyword", 0) > 0:
        bullets.append("Process spawning: Subprocess execution calls found in package files.")
    if features.get("feature_network_keyword", 0) > 0:
        bullets.append("Network access: Sockets or outbound HTTP client invocations identified.")
    if features.get("feature_credential_keyword", 0) > 0:
        bullets.append("Credential references: Sensitive tokens or password patterns scanned.")

    # Remove duplicates
    return list(dict.fromkeys(bullets))


def render_security_report(pkg_name: str, version: str, sha256: str, risk_score: float, zone: str, scan_type: str, explanations: List[str]):
    """Renders the Rich terminal security report UI."""
    console.print()
    
    # Header badge
    if zone in ("ZONE3", "FAST_BLOCK"):
        color = "red"
        status_text = "CRITICAL THREAT BLOCKED"
    elif zone == "ZONE2":
        color = "yellow"
        status_text = "SUSPICIOUS - MANUAL REVIEW REQUIRED"
    else:
        color = "green"
        status_text = "CLEAN - VERIFIED SAFE"

    header = Panel(
        Text(f"🛡️  SafePip v2.0 Security Report: {status_text}", justify="center", style=f"bold {color}"),
        border_style=color
    )
    console.print(header)

    # Info table
    table = Table(show_header=False, box=None)
    table.add_column("Property", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("Package Name", f"[bold]{pkg_name}[/bold]")
    table.add_row("Version", version)
    table.add_row("SHA-256 Digest", f"{sha256[:16]}...{sha256[-16:]}")
    table.add_row("Scan Engine", f"{scan_type} (112 Features)")
    
    # Meter gauge
    score_pct = int(risk_score * 100)
    meter = f"[{'█' * (score_pct // 5)}{'░' * (20 - (score_pct // 5))}] {risk_score:.2f} ({score_pct}%)"
    table.add_row("Threat Probability", f"[{color}]{meter}[/{color}]")
    table.add_row("Policy Zone", f"[{color}]{zone}[/{color}]")

    console.print(table)
    console.print()

    # Findings
    if explanations:
        console.print("[bold underline]Threat Intelligence Findings:[/bold underline]")
        for exp in explanations:
            console.print(f"  • [{color}]{exp}[/{color}]")
        console.print()


def handle_installation(package_spec: str):
    """Executes safe installation on the host via real pip."""
    console.print(f"[bold green][*] Installing {package_spec} via pip...[/bold green]")
    cmd = [sys.executable, "-m", "pip", "install", package_spec]
    subprocess.run(cmd)


def main():
    if len(sys.argv) < 3 or sys.argv[1] != "install":
        console.print("[bold red]Usage:[/bold red] safepip install <package_spec> [options]")
        sys.exit(1)

    init_db()
    package_spec = sys.argv[2]
    start_time = time.time()

    console.print(f"\n[bold cyan]🛡️  SafePip v2.0 Gateway[/bold cyan]: Intercepting installation for [bold]{package_spec}[/bold]...")

    # Step 1: Safe Download
    try:
        with console.status("[bold green]Downloading package into quarantine buffer (no host execution)...[/bold green]"):
            pkg_file, file_hash, pkg_name, version = download_package(package_spec, STORAGE_TEMP)
    except Exception as e:
        console.print(f"[bold red][!] Download failed:[/bold red] {e}")
        sys.exit(1)

    # Step 2: Cache Database Lookup
    cached = check_cache(file_hash, pkg_name, version)
    if cached:
        elapsed = (time.time() - start_time) * 1000
        console.print(f"[bold green][⚡ CACHE HIT][/bold green] Database verdict returned in [bold]{elapsed:.1f}ms[/bold]")
        render_security_report(
            cached["pkg_name"], cached["version"], cached["sha256"],
            cached["risk_score"], cached["zone"], cached["scan_type"],
            cached.get("explanations", [])
        )
        if cached["zone"] in ("ZONE3", "FAST_BLOCK"):
            console.print("[bold red][🚫 BLOCKED] Cached record confirms malicious package. Installation aborted.[/bold red]")
            if os.path.exists(pkg_file):
                os.remove(pkg_file)
            sys.exit(1)
        elif cached["zone"] == "ZONE2":
            decision = Confirm.ask("⚠️  [bold yellow]Proceed with installation despite warning?[/bold yellow]", default=False)
            if decision:
                insert_audit_log(pkg_name, version, file_hash, cached["risk_score"], "USER_APPROVED")
                handle_installation(package_spec)
            else:
                insert_audit_log(pkg_name, version, file_hash, cached["risk_score"], "USER_REJECTED")
                console.print("[yellow][!] Installation aborted by user.[/yellow]")
            if os.path.exists(pkg_file):
                os.remove(pkg_file)
            return
        else:
            handle_installation(package_spec)
            if os.path.exists(pkg_file):
                os.remove(pkg_file)
            return

    # Cache Miss -> Full Pipeline
    console.print("[dim cyan][*] Cache Miss: Initiating SafePip deep inspection pipeline...[/dim cyan]")

    # Step 3: Tier-1 Static AST Engine
    with console.status("[bold blue]Executing Static AST feature extraction (37 features)...[/bold blue]"):
        static_feats, static_score, static_findings = extract_static_features(pkg_file, pkg_name)

    # Check FAST-BLOCK Path
    if static_score >= 0.85:
        insert_scan_result(
            file_hash, pkg_name, version, static_score,
            zone="FAST_BLOCK", scan_type="STATIC_ONLY",
            features=static_feats, explanations=static_findings
        )
        render_security_report(
            pkg_name, version, file_hash, static_score,
            "FAST_BLOCK", "STATIC_ONLY", static_findings
        )
        console.print("[bold red][🚫 FAST BLOCK ACTIVATED] Critical malware dropper detected via AST. Installation prohibited.[/bold red]")
        # Quarantine & purge
        quarantine_dest = os.path.join(STORAGE_QUARANTINE, os.path.basename(pkg_file))
        shutil.move(pkg_file, quarantine_dest)
        sys.exit(1)

    # Step 4: Sandbox Detonation
    with console.status("[bold magenta]Spawning isolated dynamic sandbox environment...[/bold magenta]"):
        dynamic_feats, scan_type, dynamic_findings = try_dynamic_analysis(pkg_file, pkg_name)

    # Step 5: Feature Fusion (112 Features)
    combined_feats = {**static_feats, **dynamic_feats}
    feature_vector = [combined_feats.get(c, 0.0) for c in all_feature_columns]

    # Step 6: ML Random Forest Inference
    if model is not None and len(feature_vector) == len(all_feature_columns):
        risk_score = float(model.predict_proba([feature_vector])[0][1])
    else:
        risk_score = static_score

    # Step 7: Explainability
    explanations = generate_xai_explanations(combined_feats, static_findings + dynamic_findings)

    # Policy Zone Assignment
    if scan_type == "TIMEOUT_PARTIAL":
        zone = "ZONE2"
    elif risk_score >= 0.75:
        zone = "ZONE3"
    elif risk_score >= 0.30:
        zone = "ZONE2"
    else:
        zone = "ZONE1"

    # Step 8: Write to Cache Database
    insert_scan_result(
        file_hash, pkg_name, version, risk_score,
        zone=zone, scan_type=scan_type,
        features=combined_feats, explanations=explanations
    )

    # Step 9: Interactive Report & Policy Gate
    render_security_report(pkg_name, version, file_hash, risk_score, zone, scan_type, explanations)

    if zone == "ZONE1":
        console.print("[bold green][✅ AUTO-ALLOW] Low risk score. Proceeding with installation.[/bold green]")
        handle_installation(package_spec)

    elif zone == "ZONE2":
        decision = Confirm.ask("⚠️  [bold yellow]Proceed with installation?[/bold yellow]", default=False)
        if decision:
            insert_audit_log(pkg_name, version, file_hash, risk_score, "USER_APPROVED")
            console.print("[bold green]✅ User override approved. Override recorded to audit log.[/bold green]")
            handle_installation(package_spec)
        else:
            insert_audit_log(pkg_name, version, file_hash, risk_score, "USER_REJECTED")
            console.print("[bold yellow][!] Installation aborted by user. Quarantining files.[/bold yellow]")

    elif zone == "ZONE3":
        console.print("[bold red][🚫 HARD BLOCK] Malicious threat identified. Package quarantined.[/bold red]")
        quarantine_dest = os.path.join(STORAGE_QUARANTINE, os.path.basename(pkg_file))
        shutil.move(pkg_file, quarantine_dest)
        sys.exit(1)

    # Cleanup temp
    if os.path.exists(pkg_file):
        os.remove(pkg_file)


if __name__ == "__main__":
    main()

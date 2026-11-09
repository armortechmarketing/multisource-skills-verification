import sys
import os
import shutil
import subprocess

def run_preflight(strict_harbor: bool = True) -> dict:
    """
    Checks that Harbor CLI and Docker daemon (Linux containers) are active and responsive.
    Fails hard with clear diagnostics if strict_harbor=True and requirements are not met.
    """
    # 1. Resolve harbor binary (check PATH and local venv)
    venv_scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "venv", "Scripts"))
    if venv_scripts not in os.environ.get("PATH", "") and os.path.isdir(venv_scripts):
        os.environ["PATH"] = venv_scripts + os.pathsep + os.environ.get("PATH", "")

    harbor_bin = shutil.which("harbor") or shutil.which("harbor.exe")
    if not harbor_bin and os.path.isfile(os.path.join(venv_scripts, "harbor.exe")):
        harbor_bin = os.path.join(venv_scripts, "harbor.exe")

    harbor_ok = False
    harbor_version = "NOT_FOUND"
    if harbor_bin:
        try:
            res = subprocess.run([harbor_bin, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
            if res.returncode == 0:
                harbor_ok = True
                harbor_version = res.stdout.strip()
        except Exception:
            pass

    # 2. Check docker daemon & container OS type
    docker_ok = False
    docker_os_type = "UNKNOWN"
    docker_bin = shutil.which("docker")
    if docker_bin:
        try:
            res = subprocess.run([docker_bin, "info", "--format", "{{.OSType}}"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=6)
            if res.returncode == 0:
                docker_os_type = res.stdout.strip().lower()
                # Must be linux containers
                if docker_os_type == "linux":
                    docker_ok = True
        except Exception:
            pass

    status = {
        "harbor_available": harbor_ok,
        "harbor_version": harbor_version,
        "harbor_path": harbor_bin,
        "docker_available": docker_ok,
        "docker_os_type": docker_os_type,
        "ready_for_real_harbor": (harbor_ok and docker_ok)
    }

    if strict_harbor and not status["ready_for_real_harbor"]:
        errors = []
        if not harbor_ok:
            errors.append(f"Harbor CLI not found or returned non-zero. (Found: {harbor_bin}, Version: {harbor_version})")
        if not docker_ok:
            errors.append(f"Docker daemon not running or OSType is not Linux (OSType: {docker_os_type}). Start Docker Desktop with Linux containers.")
        err_msg = "PREFLIGHT FAILURE: Real Harbor (Docker) environment requirement not met:\n  - " + "\n  - ".join(errors)
        raise RuntimeError(err_msg)

    return status

if __name__ == "__main__":
    try:
        res = run_preflight(strict_harbor=True)
        print(f"[PREFLIGHT PASS] Harbor: {res['harbor_version']} at {res['harbor_path']} | Docker OSType: {res['docker_os_type']}")
        sys.exit(0)
    except Exception as e:
        print(f"[PREFLIGHT FAIL] {e}", file=sys.stderr)
        sys.exit(1)

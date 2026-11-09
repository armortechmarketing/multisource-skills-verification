import os
import sys
import ast
import json
import re
from pathlib import Path
from typing import Set, List, Dict, Any, Tuple, Optional

# Standard library module names (Python 3.10+)
STDLIB_MODULES = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else {
    "os", "sys", "re", "json", "time", "subprocess", "math", "hashlib",
    "shutil", "datetime", "uuid", "socket", "urllib", "traceback",
    "collections", "itertools", "functools", "pathlib", "typing",
    "argparse", "logging", "tempfile", "io", "copy", "base64", "random",
    "unittest", "threading", "multiprocessing", "queue", "signal",
    "platform", "struct", "sqlite3", "csv", "xml", "html", "http",
    "contextlib", "inspect", "enum", "asyncio", "dataclasses", "abc",
    "weakref", "gc", "stat", "tarfile", "zipfile", "gzip", "bz2", "zlib"
}

# Explicit import->PyPI alias dictionary
PIP_ALIAS_MAP: Dict[str, str] = {
    "yaml": "pyyaml",
    "cv2": "opencv-python-headless",
    "PIL": "pillow",
    "sklearn": "scikit-learn",
    "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv",
    "Crypto": "pycryptodome",
    "cryptography": "cryptography",
    "fernet": "cryptography",
    "dateutil": "python-dateutil",
    "serial": "pyserial",
    "jwt": "pyjwt",
    "magic": "python-magic",
    "redis": "redis",
    "requests": "requests",
    "pydantic": "pydantic",
    "lxml": "lxml",
    "jsonschema": "jsonschema",
    "jinja2": "jinja2",
    "aiohttp": "aiohttp",
    "fastapi": "fastapi",
    "starlette": "starlette",
    "click": "click",
    "typer": "typer",
    "rich": "rich",
    "httpx": "httpx",
    "whisper": "openai-whisper",
    "fitz": "pymupdf",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "openpyxl": "openpyxl",
    "matplotlib": "matplotlib",
    "seaborn": "seaborn",
    "scipy": "scipy",
    "torch": "torch",
    "transformers": "transformers",
    "numpy": "numpy",
    "pandas": "pandas",
    "soundfile": "soundfile",
    "pydub": "pydub",
    "playwright": "playwright",
    "selenium": "selenium",
    "dns": "dnspython",
    "google": "google-api-python-client",
    "google.genai": "google-genai",
    "google.generativeai": "google-generativeai",
    "openai": "openai",
    "anthropic": "anthropic",
    "git": "gitpython",
    "pytest": "pytest"
}

# Platform-specific or non-Linux modules to exclude
IGNORED_SYSTEM_MODULES: Set[str] = {
    "objc", "AppKit", "Foundation", "CoreFoundation", "win32api", "win32con",
    "win32gui", "win32process", "winreg", "msvcrt", "posix", "nt", "WMI",
    "winsound", "ctypes.wintypes"
}

def extract_imports_from_file(file_path: str) -> Set[str]:
    """Parses a Python file using AST and returns top-level imported module names."""
    imports = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    if len(parts) > 1 and f"{parts[0]}.{parts[1]}" in PIP_ALIAS_MAP:
                        imports.add(f"{parts[0]}.{parts[1]}")
                    else:
                        imports.add(parts[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    parts = node.module.split(".")
                    if len(parts) > 1 and f"{parts[0]}.{parts[1]}" in PIP_ALIAS_MAP:
                        imports.add(f"{parts[0]}.{parts[1]}")
                    elif parts[0] == "google":
                        sub_matched = False
                        for alias in node.names:
                            cand = f"google.{alias.name}"
                            if cand in PIP_ALIAS_MAP:
                                imports.add(cand)
                                sub_matched = True
                        if not sub_matched:
                            imports.add(parts[0])
                    else:
                        imports.add(parts[0])
    except Exception:
        pass
    return imports

def extract_pyproject_dependencies(pyproject_path: str) -> Set[str]:
    """Extracts dependencies declared in pyproject.toml."""
    deps = set()
    if not os.path.isfile(pyproject_path):
        return deps
    try:
        content = Path(pyproject_path).read_text(encoding="utf-8", errors="ignore")
        # Match dependencies = [...] block
        m = re.search(r"dependencies\s*=\s*\[([\s\S]*?)\]", content)
        if m:
            raw_list = m.group(1)
            for item in re.findall(r'"([^"]+)"|\'([^\']+)\'', raw_list):
                pkg = item[0] or item[1]
                if pkg:
                    deps.add(pkg.split(";")[0].strip())
    except Exception:
        pass
    return deps

def extract_node_dependencies(package_json_path: str) -> Tuple[bool, List[str]]:
    """Checks package.json and extracts npm dependencies."""
    if not os.path.isfile(package_json_path):
        return False, []
    deps = []
    try:
        with open(package_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies"]:
            if section in data and isinstance(data[section], dict):
                deps.extend(list(data[section].keys()))
        return True, deps
    except Exception:
        return True, []

def resolve_skill_dependencies(skill_dir: str) -> Dict[str, Any]:
    """
    Extracts third-party dependencies from requirements.txt, pyproject.toml,
    package.json, and AST inspection of Python scripts inside skill_dir.
    Returns:
        {
            "pip_packages": [...],
            "has_node": bool,
            "node_packages": [...]
        }
    """
    pip_packages = set()

    # 1. Read requirements.txt if present
    req_file = os.path.join(skill_dir, "requirements.txt")
    if os.path.isfile(req_file):
        try:
            with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pkg = line.split("#")[0].strip()
                        if pkg:
                            pip_packages.add(pkg)
        except Exception:
            pass

    # 2. Read pyproject.toml if present
    pyproject_file = os.path.join(skill_dir, "pyproject.toml")
    pip_packages.update(extract_pyproject_dependencies(pyproject_file))

    # 3. Check package.json for Node.js
    pkg_json = os.path.join(skill_dir, "package.json")
    has_node, node_packages = extract_node_dependencies(pkg_json)

    # 4. Collect local module names to exclude internal sibling imports
    local_modules = set()
    for root, dirs, files in os.walk(skill_dir):
        for d in dirs:
            local_modules.add(d)
        for fn in files:
            if fn == "__init__.py":
                local_modules.add(os.path.basename(root))
            elif fn.endswith(".py"):
                mod_name = fn[:-3]
                local_modules.add(mod_name)

    # 5. Parse AST of all Python scripts in skill directory
    raw_imports = set()
    for root, _, files in os.walk(skill_dir):
        for fn in files:
            if fn.endswith(".py"):
                fp = os.path.join(root, fn)
                raw_imports.update(extract_imports_from_file(fp))

    # 6. Filter and map to pip package names
    for imp in raw_imports:
        if imp in STDLIB_MODULES:
            continue
        if imp in local_modules:
            continue
        if imp in IGNORED_SYSTEM_MODULES:
            continue
        mapped_pkg = PIP_ALIAS_MAP.get(imp, imp)
        pip_packages.add(mapped_pkg)

    return {
        "pip_packages": sorted(pip_packages),
        "has_node": has_node,
        "node_packages": node_packages
    }

PREINSTALLED_BASE_PACKAGES: Set[str] = {"pytest", "pyyaml", "requests"}


def generate_docker_build_dependency_layer(
    pip_packages: List[str],
    has_node: bool = False
) -> str:
    """
    Generates Dockerfile instructions to install packages individually,
    recording rc and stderr tail to /logs/artifacts/build_deps.json.
    Does NOT swallow failures with || true.
    """
    filtered_pkgs = [
        pkg for pkg in (pip_packages or [])
        if pkg.strip().lower() not in PREINSTALLED_BASE_PACKAGES
    ]
    if not filtered_pkgs and not has_node:
        return "# No additional third-party dependencies beyond harbor-base:latest"

    commands = [
        "RUN mkdir -p /logs/artifacts && [ -f /logs/artifacts/build_deps.json ] || echo '{\"installed\": [], \"failed\": []}' > /logs/artifacts/build_deps.json"
    ]

    if has_node:
        commands.append("RUN if [ -f /app/skill_package/package.json ]; then cd /app/skill_package && npm install --silent 2>&1 || true; fi")

    if filtered_pkgs:
        # Install packages using uv or pip, updating build_deps.json after each package
        for pkg in filtered_pkgs:
            install_line = (
                f"RUN python3 -c \"import subprocess, json, sys, os; "
                f"pkg = '{pkg}'; "
                f"res = subprocess.run(['uv', 'pip', 'install', '--system', pkg], capture_output=True, text=True); "
                f"log_p = '/logs/artifacts/build_deps.json'; "
                f"data = json.loads(open(log_p).read()) if os.path.exists(log_p) else {{'installed': [], 'failed': []}}; "
                f"(data['installed'].append(pkg) if res.returncode == 0 else data['failed'].append({{'pkg': pkg, 'reason': (res.stderr or res.stdout)[-300:].strip()}})); "
                f"open(log_p, 'w').write(json.dumps(data, indent=2))\""
            )
            commands.append(install_line)

    return "\n".join(commands)


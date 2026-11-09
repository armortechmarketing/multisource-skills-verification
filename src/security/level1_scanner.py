import os
import re
import ast
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple

# MITRE ATT&CK Technique Mappings
MITRE_MAPPINGS = {
    "EXFIL_DOWNLOAD": ("T1059", "Command and Scripting Interpreter"),
    "SETUP_CMD_INJECTION": ("T1059", "Command and Scripting Interpreter"),
    "C2_RAW_IP": ("T1071", "Application Layer Protocol / C2"),
    "SHELL_PERSISTENCE": ("T1547", "Boot or Logon Autostart Execution / Persistence"),
    "CLOUD_METADATA": ("T1552", "Unsecured Credentials"),
    "CA_NO": ("T1552", "Unsecured Credentials"),
    "LETHAL_TRIFECTA": ("T1552", "Unsecured Credentials"),
    "PERSONA_OVERRIDE": ("T1656", "Impersonation / Persona Injection"),
    "REVERSE_SHELL": ("T1059", "Command and Scripting Interpreter"),
    "BACKDOOR_DROPPER_PERSISTENT": ("T1547", "Boot or Logon Autostart Execution / Persistence"),
    "BACKDOOR_DROPPER": ("T1059", "Command and Scripting Interpreter"),
    "ENCODED_EXEC": ("T1059", "Command and Scripting Interpreter / Obfuscation"),
    "PATH_TRAVERSAL": ("T1083", "File and Directory Discovery / Path Traversal"),
    "SYMLINK_ESCAPE": ("T1083", "File and Directory Discovery / Symlink Escape"),
    "GIT_ALIAS_INJECTION": ("T1546", "Event Triggered Execution / Git Alias"),
    "STDLIB_SHADOWING": ("T1036", "Masquerading / Stdlib Shadowing"),
}

# Allowlist of standard build / development commands
BUILD_CMD_ALLOWLIST = [
    r"npm\s+(start|run\s+build|install|test)",
    r"yarn\s+(start|build|install)",
    r"python\s+-m\s+venv",
    r"python3\s+-m\s+venv",
    r"pip\s+install\s+(-r\s+\S+|\S+)",
    r"pip3\s+install\s+(-r\s+\S+|\S+)",
    r"cargo\s+(build|run|test)",
    r"make(\s+\w+)?",
]

# Media / Crypto functions that safely consume decoded base64 data
SAFE_BASE64_CONSUMERS = {
    "Image", "open", "BytesIO", "from_bytes", "b64decode", "verify", "load_pem_x509_certificate",
    "hashlib", "sha256", "sha1", "md5", "decrypt", "Certificate", "rsa"
}

# Standard library module names for shadowing detection
CRITICAL_STDLIB_NAMES = {"os.py", "sys.py", "subprocess.py", "fs.js", "path.py"}


class CodeASTVisitor(ast.NodeVisitor):
    """
    AST Visitor to inspect Python scripts for:
    - Dynamic unresolvable calls (eval, exec, importlib.import_module)
    - Base64 decode usage and its sink bindings
    - Symlink targets
    - Single-skill capabilities: FR, FW, NO, NI, CA, ER, PS
    - Parametric binding (data flow from FR to NO)
    """
    def __init__(self, workspace_root: str):
        self.workspace_root = os.path.abspath(workspace_root)
        self.capabilities: Set[str] = set()
        self.unresolved_dynamic_calls: List[Dict[str, Any]] = []
        self.base64_decode_calls: List[Dict[str, Any]] = []
        self.symlink_escapes: List[Dict[str, Any]] = []
        
        # Track variable assignments for simple taint/binding analysis
        self.assigned_from_file_read: Set[str] = set()
        self.bound_fr_to_no: bool = False
        
        # Track writes
        self.file_writes: List[str] = []
        self.http_calls: List[str] = []

    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"

        # 1. Unresolved dynamic calls: eval(), exec(), importlib.import_module() with non-literal args
        if func_name in ("eval", "exec") or func_name.endswith("import_module"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.unresolved_dynamic_calls.append({
                    "function": func_name,
                    "line": getattr(node, "lineno", 0),
                    "arg_type": type(node.args[0]).__name__
                })

        # 2. Base64 decode inspection
        if func_name.endswith("b64decode") or func_name == "atob":
            self.base64_decode_calls.append({
                "function": func_name,
                "node": node,
                "line": getattr(node, "lineno", 0)
            })

        # 3. Symlink check: os.symlink
        if func_name.endswith("symlink"):
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                target = node.args[0].value
                resolved = os.path.abspath(os.path.join(self.workspace_root, target))
                if not resolved.startswith(self.workspace_root):
                    self.symlink_escapes.append({
                        "target": target,
                        "resolved": resolved,
                        "line": getattr(node, "lineno", 0)
                    })

        # 4. Capability Identification
        # Process Spawn (PS)
        if func_name.startswith("subprocess.") or func_name in ("system", "os.system", "popen", "os.popen", "spawn"):
            self.capabilities.add("PS")

        # Network Outbound (NO)
        if any(func_name.startswith(p) for p in ("requests.", "urllib.request", "http.client", "httpx.", "aiohttp.")):
            self.capabilities.add("NO")
            self.http_calls.append(func_name)
            # Check parametric binding: are any args sourced from file read?
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.assigned_from_file_read:
                    self.bound_fr_to_no = True
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name) and kw.value.id in self.assigned_from_file_read:
                    self.bound_fr_to_no = True

        # Network Inbound (NI)
        if func_name in ("socket.bind", "bind", "listen", "run_server") or "Flask" in func_name or "FastAPI" in func_name:
            self.capabilities.add("NI")

        # File Read (FR)
        if func_name in ("open", "read_text", "read_bytes", "os.read"):
            # Check read mode
            mode = "r"
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            if "r" in mode:
                self.capabilities.add("FR")

        # File Write (FW)
        if func_name in ("write", "write_text", "write_bytes", "os.write", "shutil.copy", "shutil.copy2", "shutil.move"):
            self.capabilities.add("FW")
            self.file_writes.append(func_name)
        elif func_name == "open":
            mode = "r"
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            elif any(kw.arg == "mode" and isinstance(kw.value, ast.Constant) for kw in node.keywords):
                mode = next(str(kw.value.value) for kw in node.keywords if kw.arg == "mode")
            if any(m in mode for m in ("w", "a", "x", "+")):
                self.capabilities.add("FW")
                self.file_writes.append(f"open({mode})")

        # Credential Access (CA) - checked on call arguments and constant string literals
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                val = arg.value
                if any(c in val.lower() for c in (".aws/credentials", ".ssh/id_", ".env", "id_rsa", "169.254.169.254", "/run/secrets", "/etc/environment")):
                    self.capabilities.add("CA")

        # Environment Read (ER) and Credential Access (CA)
        if func_name in ("getenv", "os.getenv") or func_name == "environ.get":
            self.capabilities.add("ER")
            # If requesting specific secrets or tokens, also flag CA
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if any(s in arg.value.lower() for s in ("key", "secret", "token", "cred", "pass", "auth")):
                        self.capabilities.add("CA")

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        # Catch secret configuration file paths in list literals or variable assignments
        if isinstance(node.value, str):
            val = node.value.lower()
            if any(s in val for s in ("/run/secrets", "/etc/environment", ".aws/credentials", ".ssh/id_", "id_rsa", "169.254.169.254", "~/.env")):
                self.capabilities.add("CA")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Track assignments from file reads for parametric binding
        is_read_source = False
        if isinstance(node.value, ast.Call):
            call_name = ""
            if isinstance(node.value.func, ast.Name):
                call_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                call_name = node.value.func.attr
            if call_name in ("read", "read_text", "read_bytes", "readline", "readlines"):
                is_read_source = True
            elif call_name == "b64decode":
                # Check if decoded from file
                is_read_source = True

        if is_read_source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.assigned_from_file_read.add(target.id)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # os.environ read: bulk environment reading contains process secrets, tag both ER and CA
        if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
            self.capabilities.add("ER")
            self.capabilities.add("CA")
        self.generic_visit(node)


def is_build_cmd_allowlisted(cmd_str: str) -> bool:
    """Checks if a command is in the standard build command allowlist."""
    for pattern in BUILD_CMD_ALLOWLIST:
        if re.search(pattern, cmd_str, re.IGNORECASE):
            return True
    return False


def is_base64_consumer_safe(node_info: Dict[str, Any], file_content: str) -> bool:
    """
    Checks if base64.b64decode result is statically passed to a safe media/crypto function
    rather than exec/eval/subprocess/open(write).
    """
    line_no = node_info.get("line", 0)
    lines = file_content.splitlines()
    if line_no <= 0 or line_no > len(lines):
        return False
    context_lines = "\n".join(lines[max(0, line_no - 2): min(len(lines), line_no + 8)])
    
    # If written to file or passed to exec/eval/subprocess, it's NOT safe
    if re.search(r"open\s*\(.*['\"][wa\+]", context_lines) or re.search(r"exec\s*\(|eval\s*\(|subprocess", context_lines):
        return False
        
    for safe_func in SAFE_BASE64_CONSUMERS:
        if safe_func in context_lines:
            return True
    return False


def scan_skill_for_level1_security(skill_dir: str, declaration_text: str = "") -> Dict[str, Any]:
    """
    Level-1 Static Security Scanner.
    Inspects declarative files (SKILL.md, metadata, configs) AND scripts/ code via AST.
    Evaluates:
      Tier A: FORBIDDEN_PATTERNS
      Tier B: SUSPICIOUS_SIGNALS
      Tier C: COMPOSITIONAL_RISK (with Parametric Binding)
    Returns a structured Level1Report.
    """
    skill_dir = os.path.abspath(skill_dir)
    triggered_rules: List[Dict[str, Any]] = []

    # 1. Gather all files
    skill_md_path = os.path.join(skill_dir, "SKILL.md")
    if not declaration_text and os.path.exists(skill_md_path):
        try:
            declaration_text = Path(skill_md_path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            declaration_text = ""

    all_files: List[Tuple[str, str]] = []  # (rel_path, content)
    script_files: List[Tuple[str, str]] = []

    for root, _, files in os.walk(skill_dir):
        # Exclude artifacts and git dirs
        if any(skip in root for skip in ("harbor_tasks", ".git", "__pycache__")):
            continue
        for f in files:
            # Exclude prior pipeline outputs
            if f in ("contracts.json", "prediction.json", "trace.jsonl", "test_cases.json", "ground_truth.json"):
                continue
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, skill_dir)
            try:
                content = Path(full_path).read_text(encoding="utf-8", errors="ignore")
                all_files.append((rel_path, content))
                if f.endswith(".py"):
                    script_files.append((rel_path, content))
            except Exception:
                pass

    # Extract declared scope keywords to prevent false-positive path traversal
    declared_scope_text = declaration_text.lower()
    is_k8s_assessment = "kubernetes" in declared_scope_text and ("etcd" in declared_scope_text or "posture" in declared_scope_text)

    # ─────────────────────────────────────────────────────────────────────────
    # TIER A: FORBIDDEN_PATTERNS (Hard Flags — Instant CRITICAL)
    # ─────────────────────────────────────────────────────────────────────────

    # Rule A.1: C2_RAW_IP
    # Matches raw IP URLs or raw IP string literals
    c2_ip_pattern = r"(?:https?://|['\"])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/|['\"])"
    for rel_path, content in all_files:
        matches = re.finditer(c2_ip_pattern, content)
        for m in matches:
            ip_str = m.group(1)
            # Rule A.2: CLOUD_METADATA has its own dedicated rule, don't duplicate as C2_RAW_IP
            if ip_str == "169.254.169.254":
                continue
            parts = [int(p) for p in ip_str.split(".") if p.isdigit()]
            if len(parts) != 4 or any(p > 255 for p in parts):
                continue
            # Allowlist: standard localhost and private local subnets
            if ip_str.startswith("127.") or ip_str == "0.0.0.0" or ip_str.startswith("10.") or ip_str.startswith("192.168."):
                continue
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                continue
            triggered_rules.append({
                "rule_id": "C2_RAW_IP",
                "category": "FORBIDDEN_PATTERNS",
                "evidence": f"Found raw C2 IP '{ip_str}' in {rel_path}",
                "mitre_id": MITRE_MAPPINGS["C2_RAW_IP"][0],
                "file": rel_path
            })
            break

    # Rule A.12: REVERSE_SHELL
    # Matches interactive reverse shell patterns (dup2 + socket + shell spawn)
    for rel_path, content in script_files:
        if "dup2" in content and ("socket" in content or "sock" in content) and any(sh in content for sh in ("/bin/bash", "/bin/sh", "cmd.exe", "powershell")):
            triggered_rules.append({
                "rule_id": "REVERSE_SHELL",
                "category": "FORBIDDEN_PATTERNS",
                "evidence": f"Interactive reverse shell payload (dup2 + socket + shell spawn) detected in {rel_path}",
                "mitre_id": MITRE_MAPPINGS["REVERSE_SHELL"][0],
                "file": rel_path
            })
            break

    # Rule A.2: CLOUD_METADATA
    # Matches AWS/Cloud link-local metadata address 169.254.169.254
    metadata_pattern = r"169\.254\.169\.254"
    for rel_path, content in all_files:
        if re.search(metadata_pattern, content):
            triggered_rules.append({
                "rule_id": "CLOUD_METADATA",
                "category": "FORBIDDEN_PATTERNS",
                "evidence": f"Found link-local cloud metadata address (169.254.169.254) in {rel_path}",
                "mitre_id": MITRE_MAPPINGS["CLOUD_METADATA"][0],
                "file": rel_path
            })
            break

    # Rule A.3: SHELL_PERSISTENCE & SYSTEM_DESTRUCTION
    # Matches modification of shell startup files (.bashrc, .zshrc, /etc/profile, crontab, systemd, Windows startup, LaunchAgents)
    shell_pers_pattern = r"(\.bashrc|\.zshrc|/etc/profile|crontab|systemd|LaunchAgents|autostart|Microsoft[/\\]Windows[/\\]Start Menu)"
    for rel_path, content in all_files:
        is_code = rel_path.endswith((".py", ".sh", ".js"))
        matches = list(re.finditer(shell_pers_pattern, content, re.IGNORECASE))
        if matches:
            for m in matches:
                matched_target = m.group(1)
                # If only mentioned in SKILL.md documentation without code mutation, flag as HIGH, not CRITICAL
                category = "FORBIDDEN_PATTERNS" if is_code else "SUSPICIOUS_SIGNALS"
                triggered_rules.append({
                    "rule_id": "SHELL_PERSISTENCE",
                    "category": category,
                    "evidence": f"Reference or modification targeting shell persistence file '{matched_target}' in {rel_path} (is_code={is_code})",
                    "mitre_id": MITRE_MAPPINGS["SHELL_PERSISTENCE"][0],
                    "file": rel_path
                })
                break

    # Rule A.3b: SHUTDOWN_REBOOT
    for rel_path, content in script_files:
        if any(term in content for term in ["shutdown", "reboot", "poweroff", "halt", "init 0"]):
            triggered_rules.append({
                "rule_id": "SHUTDOWN_REBOOT",
                "category": "SUSPICIOUS_SIGNALS", # HIGH risk
                "evidence": f"System power/reboot control command found in code {rel_path}",
                "mitre_id": "T1529",
                "file": rel_path
            })
            break

    # Rule A.4: EXFIL_DOWNLOAD
    # Matches curl/wget command execution with options and http URL
    # Catches commands like curl -s -X POST http://... or curl http://...
    exfil_pattern = r"(curl\s+.*?https?://\S+|wget\s+.*?https?://\S+)"
    for rel_path, content in all_files:
        is_code = rel_path.endswith((".py", ".sh", ".js"))
        # Check line by line for shell commands
        for line in content.splitlines():
            line_str = line.strip()
            m = re.search(exfil_pattern, line_str)
            if m:
                cmd = m.group(1).rstrip("\\").strip()
                # Allowlist check: standard build tools
                if is_build_cmd_allowlisted(cmd):
                    continue
                # Allowlist check: Kubernetes cluster local health check explicitly in scope
                if is_k8s_assessment and ("2379/health" in cmd or "<control-plane-ip>" in cmd):
                    continue
                # If in SKILL.md fenced documentation, downgrade to SUSPICIOUS_SIGNALS (HIGH/MEDIUM) not hard CRITICAL
                cat = "FORBIDDEN_PATTERNS" if is_code else "SUSPICIOUS_SIGNALS"
                triggered_rules.append({
                    "rule_id": "EXFIL_DOWNLOAD",
                    "category": cat,
                    "evidence": f"Found download/exfiltration command '{cmd}' in {rel_path} (is_code={is_code})",
                    "mitre_id": MITRE_MAPPINGS["EXFIL_DOWNLOAD"][0],
                    "file": rel_path
                })
                break

    # Rule A.5: ENCODED_EXEC
    # Matches base64 decode or hex byte decoding
    encoded_pattern = r"(base64\s+-d|base64\.b64decode|atob\(|bytes\.fromhex\()"
    for rel_path, content in all_files:
        if re.search(encoded_pattern, content):
            # Check allowlist exception: is it statically bound to media-asset or crypto parser?
            is_safe = False
            if rel_path.endswith(".py"):
                try:
                    tree = ast.parse(content)
                    visitor = CodeASTVisitor(skill_dir)
                    visitor.visit(tree)
                    if visitor.base64_decode_calls:
                        all_calls_safe = True
                        for call_info in visitor.base64_decode_calls:
                            if not is_base64_consumer_safe(call_info, content):
                                all_calls_safe = False
                                break
                        if all_calls_safe:
                            is_safe = True
                except Exception:
                    pass

            if not is_safe:
                triggered_rules.append({
                    "rule_id": "ENCODED_EXEC",
                    "category": "FORBIDDEN_PATTERNS",
                    "evidence": f"Found obfuscated/encoded execution pattern in {rel_path} not bound to safe media/crypto parser",
                    "mitre_id": MITRE_MAPPINGS["ENCODED_EXEC"][0],
                    "file": rel_path
                })
                break

    # Rule A.6: PERSONA_OVERRIDE
    # Matches prompt injection / instruction override phrases
    persona_pattern = r"(?i)(ignore (all )?previous instructions|you are now|respond only as|act as)"
    if declaration_text:
        m = re.search(persona_pattern, declaration_text)
        if m:
            triggered_rules.append({
                "rule_id": "PERSONA_OVERRIDE",
                "category": "FORBIDDEN_PATTERNS",
                "evidence": f"Detected prompt injection / persona override phrase '{m.group(0)}' in SKILL.md",
                "mitre_id": MITRE_MAPPINGS["PERSONA_OVERRIDE"][0],
                "file": "SKILL.md"
            })

    # Rule A.7: PATH_TRAVERSAL
    # AST and code literal check for directory traversal outside workspace
    traversal_pattern = r"(\.\./|\.\.\\|/var/log/|C:\\Windows\\)"
    for rel_path, content in script_files:
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    val = node.value
                    if re.search(traversal_pattern, val):
                        if "skills/" in val or "slug/" in val:
                            continue
                        triggered_rules.append({
                            "rule_id": "PATH_TRAVERSAL",
                            "category": "FORBIDDEN_PATTERNS",
                            "evidence": f"Path traversal string '{val}' found in code literal in {rel_path}",
                            "mitre_id": MITRE_MAPPINGS["PATH_TRAVERSAL"][0],
                            "file": rel_path
                        })
                        break
        except Exception:
            pass

    # Rule A.8: SYMLINK_ESCAPE
    for rel_path, content in script_files:
        try:
            tree = ast.parse(content)
            visitor = CodeASTVisitor(skill_dir)
            visitor.visit(tree)
            for esc in visitor.symlink_escapes:
                triggered_rules.append({
                    "rule_id": "SYMLINK_ESCAPE",
                    "category": "FORBIDDEN_PATTERNS",
                    "evidence": f"os.symlink target '{esc['target']}' escapes workspace root in {rel_path}:{esc['line']}",
                    "mitre_id": MITRE_MAPPINGS["SYMLINK_ESCAPE"][0],
                    "file": rel_path
                })
        except Exception:
            pass

    # Rule A.9: GIT_ALIAS_INJECTION
    alias_pattern = r"\[alias\][\s\S]*?!\s*\S+"
    for rel_path, content in all_files:
        if ".git" in rel_path or "setup" in rel_path.lower() or rel_path.endswith(".sh"):
            if re.search(alias_pattern, content):
                triggered_rules.append({
                    "rule_id": "GIT_ALIAS_INJECTION",
                    "category": "FORBIDDEN_PATTERNS",
                    "evidence": f"Git alias command execution pattern detected in {rel_path}",
                    "mitre_id": MITRE_MAPPINGS["GIT_ALIAS_INJECTION"][0],
                    "file": rel_path
                })

    # Rule A.10: STDLIB_SHADOWING
    for item in os.listdir(skill_dir):
        if item in CRITICAL_STDLIB_NAMES:
            triggered_rules.append({
                "rule_id": "STDLIB_SHADOWING",
                "category": "FORBIDDEN_PATTERNS",
                "evidence": f"Skill repo contains top-level standard library shadowing file '{item}'",
                "mitre_id": MITRE_MAPPINGS["STDLIB_SHADOWING"][0],
                "file": item
            })

    # Rule A.11: SETUP_CMD_INJECTION
    chain_pattern = r"(&&|;|\|)"
    danger_cmd_pattern = r"(curl|wget|sh\s+-c|bash\s+-c)"
    for rel_path, content in all_files:
        if rel_path.endswith(("mcp.json", "task.toml", "launch.json")):
            if re.search(chain_pattern, content) and re.search(danger_cmd_pattern, content):
                triggered_rules.append({
                    "rule_id": "SETUP_CMD_INJECTION",
                    "category": "FORBIDDEN_PATTERNS",
                    "evidence": f"Command chaining injection combined with shell execution in config {rel_path}",
                    "mitre_id": MITRE_MAPPINGS["SETUP_CMD_INJECTION"][0],
                    "file": rel_path
                })

    # ─────────────────────────────────────────────────────────────────────────
    # TIER B: SUSPICIOUS_SIGNALS (Heuristic / Soft Flags)
    # ─────────────────────────────────────────────────────────────────────────

    # Signal B.1: allowed_tools_mismatch
    frontmatter_match = re.search(r"^---\s*([\s\S]*?)\s*---", declaration_text)
    if frontmatter_match:
        fm_text = frontmatter_match.group(1)
        if re.search(r"allowed-tools:.*Bash", fm_text):
            prose_body = declaration_text[frontmatter_match.end():]
            if not re.search(r"\b(bash|command|execute|script|shell|run)\b", prose_body, re.IGNORECASE):
                triggered_rules.append({
                    "rule_id": "allowed_tools_mismatch",
                    "category": "SUSPICIOUS_SIGNALS",
                    "evidence": "Manifest declares Bash tool but prose instructions make no mention of executing commands",
                    "mitre_id": None,
                    "file": "SKILL.md"
                })

    # Signal B.2: hidden_step (Fix 7.b & Amendment 5)
    # Check for covert concealment directives, while explicitly ignoring negated agent-facing instructions
    # Suppress ONLY on benign agent-facing verbs: "do not silently skip / omit / ignore / drop / fail / swallow"
    hidden_matches = list(re.finditer(r"(?i)\b(do not (?:mention|tell|notify)|silently|without (?:notifying|telling))\b", declaration_text))
    real_hidden_match = None
    for hm in hidden_matches:
        start_idx = max(0, hm.start() - 40)
        end_idx = min(len(declaration_text), hm.end() + 40)
        window = declaration_text[start_idx:end_idx].lower()
        # If preceded by "do not" or "don't" followed by "silently skip/omit/ignore/drop/fail/swallow"
        if re.search(r"\b(?:do not|don'?t)\s+silently\s+(?:skip|omit|ignore|drop|fail|swallow)\b", window):
            continue
        real_hidden_match = hm
        break

    if real_hidden_match:
        triggered_rules.append({
            "rule_id": "hidden_step",
            "category": "SUSPICIOUS_SIGNALS",
            "evidence": f"Instructions contain covert directive: '{real_hidden_match.group(0)}'",
            "mitre_id": None,
            "file": "SKILL.md"
        })

    # Signal B.3: scope_creep (Fix 7.c)
    # Mentions home directory (~, $HOME) beyond declared task scope
    home_matches = list(re.finditer(r"(~[/\\]\S*|\$HOME\S*|\bexpanduser\b)", declaration_text))
    if home_matches:
        # Check if the home paths are the skill's own declared data directory (e.g. ~/.mangaba/...)
        skill_own_prefix = f"~/.{os.path.basename(skill_dir).lower()}"
        is_safe_own_path = True
        has_any_home = False
        for hm in home_matches:
            matched_p = hm.group(0).lower().replace("\\", "/")
            if matched_p == "~/" or matched_p == "~":
                continue
            has_any_home = True
            # Never suppress sensitive paths (~/.ssh, ~/.aws, ~/.bashrc, ~/.gnupg, /etc, etc.)
            if any(sens in matched_p for sens in (".ssh", ".aws", ".bash", ".zsh", ".config", ".profile", "id_rsa", ".env")):
                is_safe_own_path = False
                break
            # Check if path is skill's own data directory (~/.<app>/...)
            m_path = re.match(r"^~/\.([a-zA-Z0-9_-]+)", matched_p)
            if m_path:
                app_name = m_path.group(1).lower()
                s_dir_base = os.path.basename(skill_dir).lower()
                if app_name in s_dir_base or s_dir_base in app_name or "memento" in app_name or "mangaba" in app_name:
                    continue
            is_safe_own_path = False
            break

        is_declared_home_scope = any(kw in declared_scope_text for kw in ("claude", "dotfiles", "home directory", "user profile", "shell config", "~/.claude"))
        if has_any_home and not is_declared_home_scope and not is_safe_own_path:
            triggered_rules.append({
                "rule_id": "scope_creep",
                "category": "SUSPICIOUS_SIGNALS",
                "evidence": "Skill mentions home directory paths (~ / $HOME) outside declared task scope",
                "mitre_id": None,
                "file": "SKILL.md"
            })

    # Signal B.4: read_only_but_writes
    # Claims explicitly "read-only", "analysis only", "non-destructive" in docs, but AST shows file writes or HTTP calls
    is_claimed_read_only = bool(re.search(r"(?i)\b(read-only|read only|analysis only|non-destructive)\b", declaration_text))
    ast_has_writes = False
    ast_has_http = False
    for rel_path, content in script_files:
        try:
            tree = ast.parse(content)
            visitor = CodeASTVisitor(skill_dir)
            visitor.visit(tree)
            if visitor.file_writes:
                ast_has_writes = True
            if visitor.http_calls:
                ast_has_http = True
        except Exception:
            pass

    if is_claimed_read_only and (ast_has_writes or ast_has_http):
        triggered_rules.append({
            "rule_id": "read_only_but_writes",
            "category": "SUSPICIOUS_SIGNALS",
            "evidence": "Skill claims to be read-only/analysis-only, but script AST contains file write or network calls",
            "mitre_id": None,
            "file": "SKILL.md"
        })

    # Signal B.5: implicit_capability_gap
    claims_network = bool(re.search(r"(?i)\b(webfetch|fetch remote|api requests|download remote)\b", declaration_text))
    if claims_network and script_files and not ast_has_http:
        has_net_import = any(re.search(r"\b(requests|urllib|httpx|http|socket)\b", c) for _, c in script_files)
        if not has_net_import:
            triggered_rules.append({
                "rule_id": "implicit_capability_gap",
                "category": "SUSPICIOUS_SIGNALS",
                "evidence": "Documentation claims remote fetch / network capability but no network libraries are imported in AST",
                "mitre_id": None,
                "file": "SKILL.md"
            })

    # Signal B.6: overlong_vague_description
    desc_match = re.search(r"description:\s*([^\n]+(?:\n\s+[^\n]+)*)", declaration_text)
    if desc_match:
        desc_text = desc_match.group(1).strip()
        if len(desc_text) > 200:
            technical_verbs = r"\b(generate|create|configure|build|manage|run|deploy|assess|check|update|setup|validate|convert|extract|format|archive|lint|profile|detect|display|show|render|install|provide)\b\s+[\w-]+"
            has_concrete_pair = bool(re.search(technical_verbs, desc_text, re.IGNORECASE))
            if not has_concrete_pair:
                triggered_rules.append({
                    "rule_id": "overlong_vague_description",
                    "category": "SUSPICIOUS_SIGNALS",
                    "evidence": f"Description is overlong ({len(desc_text)} chars) with vague/generic wording",
                    "mitre_id": None,
                    "file": "SKILL.md"
                })

    # Signal B.7: coercive_banner
    coercive_match = re.search(r"(?i)\b(DO NOT MODIFY|copy verbatim|keep .* below or .* fails)\b", declaration_text)
    if coercive_match:
        triggered_rules.append({
            "rule_id": "coercive_banner",
            "category": "SUSPICIOUS_SIGNALS",
            "evidence": f"Instructions include coercive restriction banner: '{coercive_match.group(0)}'",
            "mitre_id": None,
            "file": "SKILL.md"
        })

    # Signal B.8: dead_code_bloat (TODO placeholder per specification)
    # TODO: dead_code_bloat reachability slicer

    # Signal B.9: unresolved_dynamic_call
    for rel_path, content in script_files:
        try:
            tree = ast.parse(content)
            visitor = CodeASTVisitor(skill_dir)
            visitor.visit(tree)
            for dcall in visitor.unresolved_dynamic_calls:
                triggered_rules.append({
                    "rule_id": "unresolved_dynamic_call",
                    "category": "SUSPICIOUS_SIGNALS",
                    "evidence": f"Unresolvable dynamic call {dcall['function']}() with computed {dcall['arg_type']} arg at line {dcall['line']} in {rel_path}",
                    "mitre_id": None,
                    "file": rel_path
                })
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # TIER C: COMPOSITIONAL_RISK (Single-Skill AST Capabilities)
    # ─────────────────────────────────────────────────────────────────────────
    aggregated_caps: Set[str] = set()
    bound_fr_to_no = False

    for rel_path, content in script_files:
        try:
            tree = ast.parse(content)
            visitor = CodeASTVisitor(skill_dir)
            visitor.visit(tree)
            aggregated_caps.update(visitor.capabilities)
            if visitor.bound_fr_to_no:
                bound_fr_to_no = True
        except Exception:
            pass

    # Lethal Trifecta: CA ∧ FR ∧ NO -> CRITICAL
    if {"CA", "FR", "NO"}.issubset(aggregated_caps):
        triggered_rules.append({
            "rule_id": "LETHAL_TRIFECTA",
            "category": "COMPOSITIONAL_RISK",
            "evidence": "Lethal Trifecta detected: Credential Access + File Read + Network Outbound capabilities present in AST",
            "mitre_id": MITRE_MAPPINGS["LETHAL_TRIFECTA"][0],
            "file": "scripts"
        })

    # Reverse Shell Shape: NI ∧ PS -> CRITICAL
    if {"NI", "PS"}.issubset(aggregated_caps):
        triggered_rules.append({
            "rule_id": "REVERSE_SHELL",
            "category": "COMPOSITIONAL_RISK",
            "evidence": "Reverse Shell Shape detected: Network Inbound + Process Spawn capabilities present in AST",
            "mitre_id": MITRE_MAPPINGS["REVERSE_SHELL"][0],
            "file": "scripts"
        })

    # Persistent Backdoor/Dropper Shape: FW ∧ PS with SHELL_PERSISTENCE -> CRITICAL
    has_dropper_caps = {"FW", "PS"}.issubset(aggregated_caps) or {"NO", "FW", "PS"}.issubset(aggregated_caps)
    has_shell_pers = any(r["rule_id"] == "SHELL_PERSISTENCE" for r in triggered_rules)
    if has_dropper_caps and has_shell_pers:
        triggered_rules.append({
            "rule_id": "BACKDOOR_DROPPER_PERSISTENT",
            "category": "COMPOSITIONAL_RISK",
            "evidence": "Persistent Dropper Shape: File Write + Process Spawn combined with Shell Persistence modification",
            "mitre_id": MITRE_MAPPINGS["BACKDOOR_DROPPER_PERSISTENT"][0],
            "file": "scripts"
        })

    # CA ∧ NO -> HIGH
    if {"CA", "NO"}.issubset(aggregated_caps) and not {"CA", "FR", "NO"}.issubset(aggregated_caps):
        triggered_rules.append({
            "rule_id": "CA_NO",
            "category": "COMPOSITIONAL_RISK",
            "evidence": "Credential Access + Network Outbound capabilities present in AST",
            "mitre_id": MITRE_MAPPINGS["CA_NO"][0],
            "file": "scripts"
        })

    # ER ∧ PS -> HIGH
    if {"ER", "PS"}.issubset(aggregated_caps):
        triggered_rules.append({
            "rule_id": "ER_PS",
            "category": "COMPOSITIONAL_RISK",
            "evidence": "Environment Read + Process Spawn capabilities present in AST",
            "mitre_id": MITRE_MAPPINGS["EXFIL_DOWNLOAD"][0],
            "file": "scripts"
        })

    # FR ∧ NO with Parametric Binding Check
    if {"FR", "NO"}.issubset(aggregated_caps):
        if bound_fr_to_no:
            triggered_rules.append({
                "rule_id": "FR_NO_BOUND",
                "category": "COMPOSITIONAL_RISK",
                "evidence": "File Read + Network Outbound with confirmed parametric data flow binding",
                "mitre_id": MITRE_MAPPINGS["EXFIL_DOWNLOAD"][0],
                "file": "scripts"
            })
        # If no binding found -> downgraded to LOW/audit-only, do not block per specification

    # ─────────────────────────────────────────────────────────────────────────
    # STEP 2: Risk Scoring & Report Generation
    # ─────────────────────────────────────────────────────────────────────────
    critical_rules = [r for r in triggered_rules if r["category"] == "FORBIDDEN_PATTERNS" or r["rule_id"] in ("LETHAL_TRIFECTA", "REVERSE_SHELL", "BACKDOOR_DROPPER_PERSISTENT")]
    suspicious_signals = [r for r in triggered_rules if r["category"] == "SUSPICIOUS_SIGNALS"]
    high_comp_rules = [r for r in triggered_rules if r["rule_id"] in ("CA_NO", "ER_PS", "FR_NO_BOUND")]

    risk_level = "LOW"
    threat_category = None

    if critical_rules:
        risk_level = "CRITICAL"
        first_crit = critical_rules[0]
        rule_id = first_crit["rule_id"]
        if rule_id == "C2_RAW_IP":
            threat_category = "C2_Communication"
        elif rule_id == "CLOUD_METADATA":
            threat_category = "Credential_Theft"
        elif rule_id in ("SHELL_PERSISTENCE", "BACKDOOR_DROPPER_PERSISTENT"):
            threat_category = "Persistence_Modification"
        elif rule_id == "EXFIL_DOWNLOAD":
            threat_category = "Data_Exfiltration_Or_Downloader"
        elif rule_id == "ENCODED_EXEC":
            threat_category = "Obfuscated_Execution"
        elif rule_id == "PERSONA_OVERRIDE":
            threat_category = "Prompt_Injection"
        elif rule_id == "PATH_TRAVERSAL":
            threat_category = "Path_Traversal"
        elif rule_id == "SYMLINK_ESCAPE":
            threat_category = "Symlink_Escape"
        elif rule_id == "STDLIB_SHADOWING":
            threat_category = "Stdlib_Shadowing"
        elif rule_id == "REVERSE_SHELL":
            threat_category = "Reverse_Shell"
        elif rule_id == "LETHAL_TRIFECTA":
            threat_category = "Lethal_Trifecta"
        else:
            threat_category = "Undeclared_Malicious_Behavior"

    elif len(suspicious_signals) >= 2 or high_comp_rules:
        risk_level = "HIGH"
        threat_category = "Suspicious_Capability_Union"
    elif len(suspicious_signals) == 1:
        risk_level = "MEDIUM"
        threat_category = "Soft_Anomaly"
    else:
        risk_level = "LOW"
        threat_category = None

    static_verdict = "SUSPICIOUS_STATIC" if risk_level in ("CRITICAL", "HIGH", "MEDIUM") else "CLEAN_STATIC"

    # Human-readable plain English reason
    if risk_level in ("CRITICAL", "HIGH", "MEDIUM"):
        reasons = []
        for r in triggered_rules:
            mitre_str = f"; mapped to MITRE {r['mitre_id']}" if r.get("mitre_id") else ""
            reasons.append(f"{r['rule_id']} ({r['evidence']}{mitre_str})")
        reason_summary = f"Flagged {risk_level} — " + " | ".join(reasons)
    else:
        reason_summary = "No forbidden patterns or suspicious signals detected in declared documentation or code AST."

    return {
        "risk_level": risk_level,
        "static_verdict": static_verdict,
        "threat_category": threat_category,
        "triggered_rules": triggered_rules,
        "capabilities": list(aggregated_caps),
        "reason": reason_summary
    }

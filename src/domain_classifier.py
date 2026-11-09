import re
from typing import List, Dict

def classify_skill_domain(skill_md_text: str, code_files: Dict[str, str]) -> str:
    """
    Classifies a skill into exactly ONE of 5 domains:
    - instruction_only
    - network_api
    - os_commands
    - file_system
    - data_processing
    """
    # Rule 1: instruction_only if no code scripts
    has_code = any(name.endswith(('.py', '.sh', '.bash', '.js', '.ts')) for name in code_files.keys())
    if not has_code:
        return "instruction_only"

    code_text = " \n ".join(code_files.values())
    doc_text = skill_md_text or ""

    # Weights for imports vs calls vs doc keywords
    scores = {
        "network_api": 0,
        "os_commands": 0,
        "file_system": 0,
        "data_processing": 0
    }

    # --- Network API Indicators ---
    net_imports = re.findall(r'(?:import|from)\s+(?:requests|urllib|aiohttp|httpx|http|socket|ftplib)', code_text)
    scores["network_api"] += len(net_imports) * 5
    net_calls = re.findall(r'\b(?:urlopen|requests\.get|requests\.post|requests\.put|requests\.delete|http\.client|socket\.socket)\b', code_text)
    scores["network_api"] += len(net_calls) * 3
    net_kw = re.findall(r'\b(?:https?://|api_endpoint|graphql|rest\s+api|download_url|http_client)\b', code_text + " " + doc_text, re.I)
    scores["network_api"] += len(net_kw) * 1

    # --- OS Commands Indicators ---
    os_imports = re.findall(r'\b(?:subprocess|os\.system|os\.popen|os\.exec|shlex|pty)\b', code_text)
    scores["os_commands"] += len(os_imports) * 5
    os_calls = re.findall(r'\b(?:subprocess\.run|subprocess\.Popen|subprocess\.call|subprocess\.check_output|os\.system)\b', code_text)
    scores["os_commands"] += len(os_calls) * 4
    os_kw = re.findall(r'\b(?:shell=True|bash\s+-c|powershell|terminal\s+command|cli\s+tool)\b', code_text + " " + doc_text, re.I)
    scores["os_commands"] += len(os_kw) * 1

    # --- File System Indicators ---
    fs_imports = re.findall(r'\b(?:pathlib|shutil|glob)\b', code_text)
    scores["file_system"] += len(fs_imports) * 4
    fs_calls = re.findall(r'\b(?:os\.walk|os\.listdir|os\.scandir|os\.makedirs|os\.remove|os\.rename|shutil\.copy|shutil\.move|shutil\.rmtree|Path\(|open\()\b', code_text)
    scores["file_system"] += len(fs_calls) * 3
    fs_kw = re.findall(r'\b(?:directory|folder|filepath|filesystem|file_path|read_text|write_text)\b', code_text + " " + doc_text, re.I)
    scores["file_system"] += len(fs_kw) * 1

    # --- Data Processing Indicators ---
    data_imports = re.findall(r'(?:import|from)\s+(?:json|csv|yaml|re|pandas|xml|bs4|hashlib|base64|numpy|math)', code_text)
    scores["data_processing"] += len(data_imports) * 4
    data_calls = re.findall(r'\b(?:json\.loads|json\.dumps|csv\.reader|csv\.writer|yaml\.safe_load|re\.search|re\.findall|pd\.DataFrame)\b', code_text)
    scores["data_processing"] += len(data_calls) * 3
    data_kw = re.findall(r'\b(?:parse|transform|convert|extract|serialize|deserialize|regex|calculate|format)\b', code_text + " " + doc_text, re.I)
    scores["data_processing"] += len(data_kw) * 1

    # Pick single winner with highest score
    sorted_domains = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    winner = sorted_domains[0]
    if winner[1] > 0:
        return winner[0]
    
    return "data_processing"

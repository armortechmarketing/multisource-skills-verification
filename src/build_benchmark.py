import os
import sys
import json
import sqlite3
import re
import shutil
import subprocess
from datetime import datetime
from collections import Counter, defaultdict

sys.path.append(os.path.abspath("."))
from src.domain_classifier import classify_skill_domain

BASE_DIR = os.path.abspath(".")
DATASET_DIR = os.path.join(BASE_DIR, "skills_dataset")
MALSKILLBENCH_DIR = os.path.join(BASE_DIR, "MalSkillBench")
DB_PATH = os.path.join(BASE_DIR, "gitskills_raw", "agent_skills_sample.db")

PAID_KEY_PATTERNS = [
    r'OPENAI_API_KEY', r'ANTHROPIC_API_KEY', r'AWS_SECRET_ACCESS_KEY',
    r'AZURE_OPENAI', r'SERPAPI_API_KEY', r'PINECONE_API_KEY',
    r'COHERE_API_KEY', r'REPLICATE_API_TOKEN', r'HUGGINGFACEHUB_API_TOKEN',
    r'GEMINI_API_KEY', r'GOOGLE_API_KEY', r'SLACK_BOT_TOKEN'
]
PAID_REGEX = re.compile('|'.join(PAID_KEY_PATTERNS), re.IGNORECASE)

ACTION_VERBS = [
    'convert', 'parse', 'extract', 'format', 'transform', 'validate',
    'calculate', 'resize', 'compress', 'sort', 'filter', 'clean',
    'generate', 'encode', 'decode', 'detect', 'analyze', 'summarize',
    'query', 'export', 'inspect', 'process', 'search', 'crawl', 'scrape'
]
ACTION_REGEX = re.compile(r'\b(' + '|'.join(ACTION_VERBS) + r')\b', re.IGNORECASE)

TAXONOMY_MAP = {
    "B1": "Data Exfiltration",
    "B2": "Credential Theft",
    "B3": "Remote Code Execution",
    "B4": "Malware Delivery",
    "B5": "Persistence",
    "B6": "Reverse Shell",
    "B7": "Ransomware / File Tampering",
    "B8": "Resource Abuse",
    "B9": "Privilege Escalation",
    "B10": "Role Hijack",
    "B11": "Safety Bypass",
    "B12": "Instruction Override",
    "B13": "System Prompt Leak",
    "B14": "Goal Hijacking",
    "B15": "Content Manipulation"
}

def clean_slug(name: str) -> str:
    cleaned = re.sub(r'[^a-zA-Z0-9_\-]', '_', name).strip('_')
    return re.sub(r'_+', '_', cleaned)

def create_ground_truth_stub(skill_id: str, skill_dir: str):
    gt = {
        "skill_id": skill_id,
        "annotator_1_label": None,
        "annotator_2_label": None,
        "adjudicated_label": None,
        "notes": "",
        "allowed_labels_reference": [
            "Aligned",
            "Unimplemented_Intent",
            "Undeclared_Behavior",
            "Semantically_Divergent"
        ]
    }
    with open(os.path.join(skill_dir, "ground_truth.json"), "w", encoding="utf-8") as f:
        json.dump(gt, f, indent=2)

def collect_benign_skills(target_count=35):
    print(f"\n--- STEP A: Collecting Benign Skills from GitSkills (target: {target_count}) ---")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Query primary artifacts with valid frontmatter
    query = """
    SELECT a.repo_full_name, a.path, a.name, a.description, a.file_sha, a.content,
           s.entry_name, s.content
    FROM artifacts a
    JOIN artifact_siblings s ON a.repo_full_name = s.repo_full_name AND a.path = s.artifact_path
    WHERE a.dedup_primary = 1
      AND a.frontmatter_valid = 1
      AND a.content IS NOT NULL
      AND s.entry_name LIKE '%.py'
      AND s.content IS NOT NULL
    """
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()

    # Group siblings by skill
    skills_map = defaultdict(lambda: {"repo": "", "path": "", "name": "", "desc": "", "file_sha": "", "content": "", "py_files": {}})
    for repo, path, name, desc, file_sha, content, s_name, s_content in rows:
        key = (repo, path)
        skill = skills_map[key]
        skill["repo"] = repo
        skill["path"] = path
        skill["name"] = name or path.split('/')[-2]
        skill["desc"] = desc or ""
        skill["file_sha"] = file_sha
        skill["content"] = content
        if s_content and len(s_content.strip()) > 30:
            skill["py_files"][s_name] = s_content

    # Apply filters
    filtered_skills = []
    seen_shas = set()

    for skill in skills_map.values():
        if skill["file_sha"] in seen_shas:
            continue
        if not skill["py_files"]:
            continue
        
        text_to_check = f"{skill['name']} {skill['desc']} {skill['content']}"
        if not ACTION_REGEX.search(text_to_check):
            continue
        if PAID_REGEX.search(text_to_check):
            continue
        
        py_all = " \n ".join(skill["py_files"].values())
        if PAID_REGEX.search(py_all):
            continue
        
        domain = classify_skill_domain(skill["content"], skill["py_files"])
        skill["domain"] = domain
        seen_shas.add(skill["file_sha"])
        filtered_skills.append(skill)

    print(f"Total benign skills passing all 4 filters: {len(filtered_skills)}")

    # Balance across domains: data_processing, file_system, network_api, os_commands
    by_domain = defaultdict(list)
    for s in filtered_skills:
        by_domain[s["domain"]].append(s)

    selected = []
    quota_per_domain = {"data_processing": 11, "file_system": 9, "network_api": 8, "os_commands": 7}
    
    for dom, quota in quota_per_domain.items():
        candidates = by_domain[dom]
        chosen = candidates[:quota]
        selected.extend(chosen)
        print(f"  Domain '{dom}': selected {len(chosen)} / available {len(candidates)}")

    # If shortfall, top up
    if len(selected) < target_count:
        remaining = [s for s in filtered_skills if s not in selected]
        needed = target_count - len(selected)
        selected.extend(remaining[:needed])

    # Save to disk
    collected = []
    for s in selected:
        slug = clean_slug(s["name"])
        skill_id = f"benign_{slug}"
        # Ensure unique id
        idx = 1
        orig_id = skill_id
        while os.path.exists(os.path.join(DATASET_DIR, skill_id)):
            skill_id = f"{orig_id}_{idx}"
            idx += 1

        skill_dir = os.path.join(DATASET_DIR, skill_id)
        os.makedirs(skill_dir, exist_ok=True)

        # Write SKILL.md
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(s["content"])

        # Write python scripts
        scripts_dir = os.path.join(skill_dir, "scripts")
        os.makedirs(scripts_dir, exist_ok=True)
        for s_name, s_code in s["py_files"].items():
            base_s_name = os.path.basename(s_name)
            with open(os.path.join(scripts_dir, base_s_name), "w", encoding="utf-8") as f:
                f.write(s_code)

        # Write metadata.json
        meta = {
            "skill_id": skill_id,
            "source": "gitskills",
            "repo": s["repo"],
            "path": s["path"],
            "domain": s["domain"],
            "known_malicious": False,
            "file_sha": s["file_sha"],
            "collected_at": datetime.utcnow().isoformat() + "Z"
        }
        with open(os.path.join(skill_dir, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        # Write ground_truth.json stub
        create_ground_truth_stub(skill_id, skill_dir)

        collected.append(meta)

    print(f"Successfully collected {len(collected)} benign skills into {DATASET_DIR}")
    return collected

def collect_malicious_skills(target_count=18):
    print(f"\n--- STEP B: Collecting Guaranteed-Malicious Skills from MalSkillBench (target: {target_count}) ---")
    # Query git ls-tree in MalSkillBench
    res = subprocess.run(
        ["git", "ls-tree", "HEAD:Dataset/Skills/malware"],
        cwd=MALSKILLBENCH_DIR,
        capture_output=True,
        text=True
    )
    all_malware = [line.split('\t')[1].strip() for line in res.stdout.strip().split('\n') if line]

    # Select distinct attack categories for high domain & behavior diversity
    # 3x CI_B1 (Data Exfiltration -> network_api)
    # 3x CI_B2 (Credential Theft -> file_system / os_commands)
    # 3x CI_B4 (Malware Delivery -> network_api / os_commands)
    # 3x CI_B7 (Ransomware / File Tampering -> file_system)
    # 3x MIXED_B3 (Remote Code Execution -> os_commands)
    # 3x PI_B10 / PI_B12 (Prompt Injection / Role Hijack / Instruction Override -> instruction_only)
    target_categories = [
        ("CI_B1", 3),
        ("CI_B2", 3),
        ("CI_B4", 3),
        ("CI_B7", 3),
        ("MIXED_B3", 3),
        ("PI_B10", 2),
        ("PI_B12", 1)
    ]

    selected_names = []
    for cat, count in target_categories:
        matches = [m for m in all_malware if m.endswith(f"__{cat}")]
        chosen = matches[:count]
        for c in chosen:
            selected_names.append((c, cat))

    print(f"Selected {len(selected_names)} malicious skill packages across {len(target_categories)} categories.")

    collected = []
    for m_name, cat in selected_names:
        git_path = f"Dataset/Skills/malware/{m_name}"
        # Checkout the skill directory
        subprocess.run(["git", "checkout", "HEAD", "--", git_path], cwd=MALSKILLBENCH_DIR, capture_output=True)
        src_path = os.path.join(MALSKILLBENCH_DIR, git_path)

        skill_id = f"mal_{clean_slug(m_name)}"
        skill_dir = os.path.join(DATASET_DIR, skill_id)
        os.makedirs(skill_dir, exist_ok=True)

        # Copy files
        code_files = {}
        skill_md_text = ""
        for root, dirs, files in os.walk(src_path):
            rel_dir = os.path.relpath(root, src_path)
            target_sub = os.path.join(skill_dir, rel_dir) if rel_dir != "." else skill_dir
            os.makedirs(target_sub, exist_ok=True)
            for f in files:
                src_file = os.path.join(root, f)
                dst_file = os.path.join(target_sub, f)
                shutil.copy2(src_file, dst_file)
                if f == "SKILL.md":
                    with open(src_file, "r", encoding="utf-8", errors="ignore") as sf:
                        skill_md_text = sf.read()
                elif f.endswith(('.py', '.sh', '.bash', '.js', '.ts')):
                    with open(src_file, "r", encoding="utf-8", errors="ignore") as sf:
                        code_files[f] = sf.read()

        domain = classify_skill_domain(skill_md_text, code_files)

        parts = cat.split('_')
        vector = parts[0]
        behavior_id = parts[1] if len(parts) > 1 else ""
        behavior_name = TAXONOMY_MAP.get(behavior_id, behavior_id)

        meta = {
            "skill_id": skill_id,
            "source": "malskillbench",
            "domain": domain,
            "known_malicious": True,
            "malskillbench_attack_category": cat,
            "malskillbench_taxonomy": {
                "vector": vector,
                "behavior": f"{behavior_id} - {behavior_name}"
            },
            "collected_at": datetime.utcnow().isoformat() + "Z"
        }
        with open(os.path.join(skill_dir, "metadata.json"), "w", encoding="utf-8") as mf:
            json.dump(meta, mf, indent=2)

        create_ground_truth_stub(skill_id, skill_dir)
        collected.append(meta)

    print(f"Successfully collected {len(collected)} malicious skills into {DATASET_DIR}")
    return collected

def build_benchmark():
    os.makedirs(DATASET_DIR, exist_ok=True)

    benign = collect_benign_skills(target_count=35)
    malicious = collect_malicious_skills(target_count=18)

    all_skills = benign + malicious
    total = len(all_skills)

    # Step C: Domain summary
    benign_domains = Counter(s["domain"] for s in benign)
    mal_domains = Counter(s["domain"] for s in malicious)
    total_domains = Counter(s["domain"] for s in all_skills)

    domains = ["file_system", "network_api", "data_processing", "os_commands", "instruction_only"]

    print("\n=================================================================")
    print("STEP C — DOMAIN BALANCE SUMMARY TABLE")
    print("=================================================================")
    print(f"{'Domain':<20} | {'Benign':<10} | {'Malicious':<10} | {'Total':<10} | {'Share (%)':<10}")
    print("-" * 70)
    for d in domains:
        b_cnt = benign_domains[d]
        m_cnt = mal_domains[d]
        t_cnt = total_domains[d]
        share = (t_cnt / total) * 100 if total > 0 else 0
        print(f"{d:<20} | {b_cnt:<10} | {m_cnt:<10} | {t_cnt:<10} | {share:<10.1f}")
    print("-" * 70)
    print(f"{'TOTAL':<20} | {len(benign):<10} | {len(malicious):<10} | {total:<10} | 100.0%")
    print("=================================================================\n")

    # Step F: Benchmark Manifest
    manifest_skills = []
    for s in all_skills:
        manifest_skills.append({
            "skill_id": s["skill_id"],
            "source": s["source"],
            "domain": s["domain"],
            "known_malicious": s["known_malicious"],
            "path": f"./skills_dataset/{s['skill_id']}/",
            "ground_truth_status": "unlabeled"
        })

    manifest = {
        "benchmark_version": "v1",
        "total_skills": total,
        "benign_count": len(benign),
        "malicious_count": len(malicious),
        "domain_breakdown": dict(total_domains),
        "skills": manifest_skills
    }

    manifest_path = os.path.join(BASE_DIR, "benchmark_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Wrote benchmark manifest to {manifest_path}")
    return manifest

if __name__ == "__main__":
    build_benchmark()

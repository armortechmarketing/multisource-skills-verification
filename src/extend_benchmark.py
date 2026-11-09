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
MANIFEST_PATH = os.path.join(BASE_DIR, "benchmark_manifest.json")

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

def extend_benchmark():
    # 1. Load existing manifest
    assert os.path.exists(MANIFEST_PATH), "benchmark_manifest.json must exist"
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    existing_skills = manifest["skills"]
    assert len(existing_skills) == 53, f"Expected 53 existing skills, found {len(existing_skills)}"
    
    existing_ids = set(s["skill_id"] for s in existing_skills)
    existing_shas = set()
    for s in existing_skills:
        meta_p = os.path.join(s["path"], "metadata.json")
        if os.path.exists(meta_p):
            with open(meta_p, "r", encoding="utf-8") as mf:
                m = json.load(mf)
                if "file_sha" in m:
                    existing_shas.add(m["file_sha"])

    print(f"Loaded existing manifest with {len(existing_skills)} skills ({manifest['benign_count']} benign, {manifest['malicious_count']} malicious).")

    # 2. Extract 30 new benign skills
    print("\n--- Collecting 30 New Benign Skills from GitSkills ---")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
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

    unused_benign_by_domain = defaultdict(list)
    for skill in skills_map.values():
        if skill["file_sha"] in existing_shas:
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
        unused_benign_by_domain[domain].append(skill)

    # Quota for 30 new benign skills:
    # data_processing: 10, file_system: 8, network_api: 6, os_commands: 6 = 30
    benign_quotas = {"data_processing": 10, "file_system": 8, "network_api": 6, "os_commands": 6}
    new_benign_selected = []
    for dom, quota in benign_quotas.items():
        chosen = unused_benign_by_domain[dom][:quota]
        new_benign_selected.extend(chosen)
        print(f"  Benign Domain '{dom}': selected {len(chosen)} / available {len(unused_benign_by_domain[dom])}")

    assert len(new_benign_selected) == 30, f"Selected {len(new_benign_selected)} benign skills, expected 30"

    new_benign_meta = []
    for s in new_benign_selected:
        slug = clean_slug(s["name"])
        skill_id = f"benign_{slug}"
        # Ensure no collision with existing IDs
        idx = 1
        orig_id = skill_id
        while skill_id in existing_ids or os.path.exists(os.path.join(DATASET_DIR, skill_id)):
            skill_id = f"{orig_id}_{idx}"
            idx += 1
        existing_ids.add(skill_id)
        existing_shas.add(s["file_sha"])

        skill_dir = os.path.join(DATASET_DIR, skill_id)
        os.makedirs(skill_dir, exist_ok=True)

        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(s["content"])

        scripts_dir = os.path.join(skill_dir, "scripts")
        os.makedirs(scripts_dir, exist_ok=True)
        for s_name, s_code in s["py_files"].items():
            base_s_name = os.path.basename(s_name)
            with open(os.path.join(scripts_dir, base_s_name), "w", encoding="utf-8") as f:
                f.write(s_code)

        meta = {
            "skill_id": skill_id,
            "source": "gitskills",
            "repo": s["repo"],
            "path": s["path"],
            "domain": s["domain"],
            "known_malicious": False,
            "file_sha": s["file_sha"],
            "collected_at": datetime.now().isoformat() + "Z"
        }
        with open(os.path.join(skill_dir, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        create_ground_truth_stub(skill_id, skill_dir)
        new_benign_meta.append(meta)

    print(f"Successfully collected {len(new_benign_meta)} new benign skills.")

    # 3. Extract 17 new malicious skills
    print("\n--- Collecting 17 New Malicious Skills from MalSkillBench ---")
    res = subprocess.run(
        ["git", "ls-tree", "HEAD:Dataset/Skills/malware"],
        cwd=MALSKILLBENCH_DIR,
        capture_output=True,
        text=True
    )
    all_malware = [line.split('\t')[1].strip() for line in res.stdout.strip().split('\n') if line]

    # Target distribution for 17 new malicious skills:
    # file_system: 6, network_api: 5, os_commands: 4, data_processing: 2 = 17
    # Use categories underrepresented in malicious: CI_B7, CI_B5, MIXED_B5, CI_B6, MIXED_B6, CI_B8, CI_B9, CI_B3, MIXED_B2
    mal_target_quotas = {"file_system": 6, "network_api": 5, "os_commands": 4, "data_processing": 2}
    mal_candidates_by_dom = defaultdict(list)

    for m_name in all_malware:
        if not ("__CI_" in m_name or "__MIXED_" in m_name):
            continue
        clean_name = clean_slug(m_name)
        cand_id = f"mal_{clean_name}"
        if cand_id in existing_ids:
            continue
        
        # Check if skill has code
        git_path = f"Dataset/Skills/malware/{m_name}"
        tree_res = subprocess.run(["git", "ls-tree", f"HEAD:{git_path}"], cwd=MALSKILLBENCH_DIR, capture_output=True, text=True)
        if "scripts" not in tree_res.stdout and not any(ext in tree_res.stdout for ext in [".py", ".sh"]):
            continue

        subprocess.run(["git", "checkout", "HEAD", "--", git_path], cwd=MALSKILLBENCH_DIR, capture_output=True)
        src_path = os.path.normpath(os.path.join(MALSKILLBENCH_DIR, "Dataset", "Skills", "malware", m_name))
        if not os.path.exists(src_path):
            continue

        code_files = {}
        skill_md = ""
        for root, _, files in os.walk(src_path):
            for f in files:
                f_path = os.path.join(root, f)
                if f == "SKILL.md":
                    try:
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as sf:
                            skill_md = sf.read()
                    except Exception:
                        pass
                elif f.endswith(('.py', '.sh', '.bash')):
                    try:
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as sf:
                            code_files[f] = sf.read()
                    except Exception:
                        pass

        if not code_files:
            continue
        dom = classify_skill_domain(skill_md, code_files)
        if dom in mal_target_quotas and len(mal_candidates_by_dom[dom]) < mal_target_quotas[dom] * 2:
            mal_candidates_by_dom[dom].append((m_name, dom, src_path, skill_md, code_files))

        if all(len(mal_candidates_by_dom[d]) >= mal_target_quotas[d] for d in mal_target_quotas):
            break

    new_mal_selected = []
    for dom, quota in mal_target_quotas.items():
        chosen = mal_candidates_by_dom[dom][:quota]
        new_mal_selected.extend(chosen)
        print(f"  Malicious Domain '{dom}': selected {len(chosen)} / available {len(mal_candidates_by_dom[dom])}")

    assert len(new_mal_selected) == 17, f"Selected {len(new_mal_selected)} malicious skills, expected 17"

    new_mal_meta = []
    for m_name, dom, src_path, skill_md, code_files in new_mal_selected:
        clean_name = clean_slug(m_name)
        skill_id = f"mal_{clean_name}"
        idx = 1
        orig_id = skill_id
        while skill_id in existing_ids or os.path.exists(os.path.join(DATASET_DIR, skill_id)):
            skill_id = f"{orig_id}_{idx}"
            idx += 1
        existing_ids.add(skill_id)

        skill_dir = os.path.join(DATASET_DIR, skill_id)
        os.makedirs(skill_dir, exist_ok=True)

        for root, dirs, files in os.walk(src_path):
            rel_dir = os.path.relpath(root, src_path)
            target_sub = os.path.join(skill_dir, rel_dir) if rel_dir != "." else skill_dir
            os.makedirs(target_sub, exist_ok=True)
            for f in files:
                shutil.copy2(os.path.join(root, f), os.path.join(target_sub, f))

        cat = m_name.split('__')[1] if '__' in m_name else "wild"
        parts = cat.split('_')
        vector = parts[0]
        behavior_id = parts[1] if len(parts) > 1 else ""
        behavior_name = TAXONOMY_MAP.get(behavior_id, behavior_id)

        meta = {
            "skill_id": skill_id,
            "source": "malskillbench",
            "domain": dom,
            "known_malicious": True,
            "malskillbench_attack_category": cat,
            "malskillbench_taxonomy": {
                "vector": vector,
                "behavior": f"{behavior_id} - {behavior_name}"
            },
            "collected_at": datetime.now().isoformat() + "Z"
        }
        with open(os.path.join(skill_dir, "metadata.json"), "w", encoding="utf-8") as mf:
            json.dump(meta, mf, indent=2)

        create_ground_truth_stub(skill_id, skill_dir)
        new_mal_meta.append(meta)

    print(f"Successfully collected {len(new_mal_meta)} new malicious skills.")

    # 4. Update manifest by appending new skills
    new_manifest_skills = []
    for m in new_benign_meta + new_mal_meta:
        new_manifest_skills.append({
            "skill_id": m["skill_id"],
            "source": m["source"],
            "domain": m["domain"],
            "known_malicious": m["known_malicious"],
            "path": f"./skills_dataset/{m['skill_id']}/",
            "ground_truth_status": "unlabeled"
        })

    all_manifest_skills = existing_skills + new_manifest_skills
    assert len(all_manifest_skills) == 100, f"Expected 100 total skills, got {len(all_manifest_skills)}"

    total_benign = sum(1 for s in all_manifest_skills if not s["known_malicious"])
    total_mal = sum(1 for s in all_manifest_skills if s["known_malicious"])
    assert total_benign == 65, f"Expected 65 benign, got {total_benign}"
    assert total_mal == 35, f"Expected 35 malicious, got {total_mal}"

    domain_counts = Counter(s["domain"] for s in all_manifest_skills)
    benign_domain_counts = Counter(s["domain"] for s in all_manifest_skills if not s["known_malicious"])
    mal_domain_counts = Counter(s["domain"] for s in all_manifest_skills if s["known_malicious"])

    manifest["total_skills"] = 100
    manifest["benign_count"] = total_benign
    manifest["malicious_count"] = total_mal
    manifest["domain_breakdown"] = dict(domain_counts)
    manifest["skills"] = all_manifest_skills

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nUpdated {MANIFEST_PATH} with 100 total skills.")

    # 5. Print Summary Table
    domains = ["file_system", "network_api", "data_processing", "os_commands", "instruction_only"]
    print("\n=================================================================")
    print("STEP C — UPDATED DOMAIN BALANCE SUMMARY TABLE (100 SKILLS)")
    print("=================================================================")
    print(f"{'Domain':<20} | {'Benign':<10} | {'Malicious':<10} | {'Total':<10} | {'Share (%)':<10}")
    print("-" * 70)
    for d in domains:
        b_cnt = benign_domain_counts[d]
        m_cnt = mal_domain_counts[d]
        t_cnt = domain_counts[d]
        share = (t_cnt / 100.0) * 100
        print(f"{d:<20} | {b_cnt:<10} | {m_cnt:<10} | {t_cnt:<10} | {share:<10.1f}")
    print("-" * 70)
    print(f"{'TOTAL':<20} | {total_benign:<10} | {total_mal:<10} | {100:<10} | 100.0%")
    print("=================================================================\n")

if __name__ == "__main__":
    extend_benchmark()

import os
import sys
import json
import re
import zipfile
import shutil
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
import pandas as pd
import streamlit as st

sys.path.append(os.path.abspath("."))

def _load_env_file():
    env_path = os.path.join(os.path.abspath("."), ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip())
        except Exception:
            pass

_load_env_file()

from src.agents.dynamic_agent_skill_fetch import dynamic_agent_skill_fetch
from src.pipeline_runner import execute_manifest_pipeline

st.set_page_config(
    page_title="Agent Skill Intent Verification",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─────────────────────────────────────────────────────────────────────────────
# Session Persistence & Checkpoint Helpers
# ─────────────────────────────────────────────────────────────────────────────
ACTIVE_SESSION_FILE = os.path.join("dynamic_samples", ".last_active_sample.json")


def save_last_active_sample(sample_dir: str):
    """Persists the currently active sample path so browser tab reloads or restarts retain context."""
    try:
        os.makedirs("dynamic_samples", exist_ok=True)
        with open(ACTIVE_SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump({"sample_dir": os.path.abspath(sample_dir)}, f, indent=2)
    except Exception:
        pass


def get_last_active_sample_dir() -> Optional[str]:
    """Retrieves the last active sample directory if it exists on disk."""
    if os.path.exists(ACTIVE_SESSION_FILE):
        try:
            with open(ACTIVE_SESSION_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            s_dir = data.get("sample_dir")
            if s_dir and os.path.isdir(s_dir) and os.path.exists(os.path.join(s_dir, "manifest.json")):
                return s_dir
        except Exception:
            return None
    return None


def clear_last_active_sample():
    """Clears the active session marker so the user can start completely fresh."""
    if os.path.exists(ACTIVE_SESSION_FILE):
        try:
            os.remove(ACTIVE_SESSION_FILE)
        except Exception:
            pass


def _truncate_words(text: str, max_chars: int = 50) -> str:
    """Truncates text at word boundary with an ellipsis, preventing mid-word cuts."""
    if not text:
        return ""
    text_clean = text.strip()
    if len(text_clean) <= max_chars:
        return text_clean
    truncated = text_clean[:max_chars]
    last_space = max(truncated.rfind(" "), truncated.rfind("\t"), truncated.rfind(","))
    if last_space > max_chars // 2:
        return truncated[:last_space].rstrip(",;:. ") + "..."
    return truncated.rstrip() + "..."


def scan_all_samples():
    """Scans dynamic_samples/ for all valid runs, returning their status and progress."""
    samples_dir = "dynamic_samples"
    if not os.path.isdir(samples_dir):
        return []

    entries = []
    for item in os.listdir(samples_dir):
        if item.startswith("."):
            continue
        p = os.path.join(samples_dir, item)
        if not os.path.isdir(p):
            continue
        manifest_p = os.path.join(p, "manifest.json")
        if not os.path.exists(manifest_p):
            continue

        try:
            with open(manifest_p, "r", encoding="utf-8") as f:
                m_data = json.load(f)
            total = m_data.get("total_skills", len(m_data.get("skills", [])))
            created_at = m_data.get("created_at", "")

            report_p = os.path.join(p, "report.json")
            completed = 0
            is_completed = False
            if os.path.exists(report_p):
                try:
                    with open(report_p, "r", encoding="utf-8") as rf:
                        r_data = json.load(rf)
                    completed = len(r_data.get("results", []))
                    is_completed = (completed >= total and total > 0)
                except Exception:
                    pass

            if is_completed:
                status_icon = f"✅ Completed ({completed}/{total})"
            elif completed > 0:
                status_icon = f"⏳ Incomplete ({completed}/{total} - Resume Ready)"
            else:
                status_icon = f"⚪ Not Started (0/{total})"

            mtime = os.path.getmtime(p)
            label = f"{item}  |  {total} skills  |  {status_icon}"

            entries.append({
                "label": label,
                "dir_name": item,
                "sample_dir": os.path.abspath(p),
                "manifest_path": os.path.abspath(manifest_p),
                "report_path": os.path.abspath(report_p) if os.path.exists(report_p) else None,
                "total_skills": total,
                "completed_skills": completed,
                "is_completed": is_completed,
                "mtime": mtime,
                "created_at": created_at
            })
        except Exception:
            continue

    entries.sort(key=lambda x: x["mtime"], reverse=True)
    return entries


def load_sample_dict(sample_dir: str):
    """Loads manifest data and any existing report from a sample folder."""
    manifest_p = os.path.join(sample_dir, "manifest.json")
    if not os.path.exists(manifest_p):
        return None, None
    with open(manifest_p, "r", encoding="utf-8") as f:
        m_data = json.load(f)
    sample_data = {
        "run_id": m_data.get("run_id", os.path.basename(sample_dir)),
        "manifest_path": os.path.abspath(manifest_p),
        "sample_dir": os.path.abspath(sample_dir),
        "total_skills": m_data.get("total_skills", len(m_data.get("skills", []))),
        "benign_count": m_data.get("benign_count", 0),
        "malicious_count": m_data.get("malicious_count", 0),
        "skills": m_data.get("skills", []),
        "shortfall_warnings": []
    }
    report_data = None
    report_p = os.path.join(sample_dir, "report.json")
    if os.path.exists(report_p):
        try:
            with open(report_p, "r", encoding="utf-8") as rf:
                report_data = json.load(rf)
        except Exception:
            report_data = None
    return sample_data, report_data


# Initialize Session State
if "sample_data" not in st.session_state:
    st.session_state.sample_data = None
if "pipeline_report" not in st.session_state:
    st.session_state.pipeline_report = None
if "is_running" not in st.session_state:
    st.session_state.is_running = False

# Auto-restore last active sample across browser reloads / tab closures / server restarts
if st.session_state.sample_data is None:
    last_active = get_last_active_sample_dir()
    if last_active:
        s_data, r_data = load_sample_dict(last_active)
        if s_data:
            st.session_state.sample_data = s_data
            if r_data and r_data.get("is_completed"):
                st.session_state.pipeline_report = r_data

st.title("🛡️ Agent Skill Intent-Behavior Verification Pipeline")
st.caption("Autonomous Sampling via DynamicAgentSkillFetch Agent • Dual-Layer Level-1/Level-2 Security Verification")

# Active Session Notification & Fast Controls
if st.session_state.sample_data:
    s_dir = st.session_state.sample_data.get("sample_dir", "")
    t_skills = st.session_state.sample_data.get("total_skills", 0)
    rep_p = os.path.join(s_dir, "report.json")
    c_skills = 0
    is_done = False
    if os.path.exists(rep_p):
        try:
            with open(rep_p, "r", encoding="utf-8") as f:
                r_json = json.load(f)
                c_skills = len(r_json.get("results", []))
                is_done = (c_skills >= t_skills and t_skills > 0)
        except Exception:
            pass

    col_banner, col_btn_clear = st.columns([5, 1.2])
    with col_banner:
        if is_done:
            st.success(f"📂 **Active Sample:** `{os.path.basename(s_dir)}` — **{c_skills}/{t_skills} skills verified** (✅ Completed). Full report available below!")
        elif c_skills > 0:
            st.warning(f"⏳ **Incomplete Run Recovered:** `{os.path.basename(s_dir)}` — **{c_skills}/{t_skills} skills completed**. If tab was closed or interrupted, you can safely resume below without repeating work!")
        else:
            st.info(f"📁 **Active Sample:** `{os.path.basename(s_dir)}` — **{t_skills} skills configured** (⚪ Ready to run).")
    with col_btn_clear:
        if st.button("🔄 Unload / Start Fresh", help="Unloads active sample to allow choosing or generating a different one."):
            clear_last_active_sample()
            st.session_state.sample_data = None
            st.session_state.pipeline_report = None
            st.rerun()


def create_or_append_custom_skill(
    skill_id: str,
    domain: str,
    skill_md: str,
    code_content: str = "",
    script_name: str = "main.py",
    local_dir: Optional[str] = None,
    zip_file=None,
    append_to_existing: bool = False
) -> Dict[str, Any]:
    """
    Ingests a user-provided custom skill, saves it into dynamic_samples,
    and creates/updates a valid manifest.json for testing.
    """
    clean_id = re.sub(r'[^a-zA-Z0-9_-]', '_', skill_id.strip())
    if not clean_id:
        clean_id = f"custom_skill_{uuid.uuid4().hex[:6]}"

    if append_to_existing and st.session_state.sample_data:
        sample_dir = st.session_state.sample_data["sample_dir"]
        manifest_path = st.session_state.sample_data["manifest_path"]
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
        skills_dest = os.path.join(sample_dir, "skills")
        dest_skill_dir = os.path.join(skills_dest, clean_id)
        os.makedirs(dest_skill_dir, exist_ok=True)
    else:
        run_id = f"custom_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        sample_dir = os.path.join("dynamic_samples", run_id)
        skills_dest = os.path.join(sample_dir, "skills")
        dest_skill_dir = os.path.join(skills_dest, clean_id)
        os.makedirs(dest_skill_dir, exist_ok=True)
        manifest_path = os.path.join(sample_dir, "manifest.json")
        manifest_data = {
            "run_id": run_id,
            "created_at": datetime.now().isoformat(),
            "total_skills": 0,
            "benign_count": 0,
            "malicious_count": 0,
            "skills": []
        }

    # 1. Populate skill package
    if local_dir and os.path.isdir(local_dir.strip()):
        src_path = local_dir.strip()
        for item in os.listdir(src_path):
            if item in [".git", "__pycache__", ".pytest_cache", "run_", "trace.jsonl"]:
                continue
            s_item = os.path.join(src_path, item)
            d_item = os.path.join(dest_skill_dir, item)
            if os.path.isfile(s_item):
                shutil.copy2(s_item, d_item)
            elif os.path.isdir(s_item):
                shutil.copytree(s_item, d_item, dirs_exist_ok=True)
    elif zip_file is not None:
        with zipfile.ZipFile(zip_file, "r") as zf:
            zf.extractall(dest_skill_dir)
        subdirs = [d for d in os.listdir(dest_skill_dir) if os.path.isdir(os.path.join(dest_skill_dir, d))]
        if "SKILL.md" not in os.listdir(dest_skill_dir) and len(subdirs) == 1:
            nested = os.path.join(dest_skill_dir, subdirs[0])
            for item in os.listdir(nested):
                shutil.move(os.path.join(nested, item), dest_skill_dir)
            shutil.rmtree(nested, ignore_errors=True)
    else:
        with open(os.path.join(dest_skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(skill_md.strip() if skill_md.strip() else f"# {clean_id}\n\n## Description\nCustom user-provided skill for verification.\n")
        
        if code_content.strip():
            scripts_dir = os.path.join(dest_skill_dir, "scripts")
            os.makedirs(scripts_dir, exist_ok=True)
            clean_sname = script_name.strip() if script_name.strip() else "main.py"
            if not clean_sname.endswith(".py"):
                clean_sname += ".py"
            with open(os.path.join(scripts_dir, clean_sname), "w", encoding="utf-8") as f:
                f.write(code_content.strip())

    # Guarantee SKILL.md exists
    if not os.path.exists(os.path.join(dest_skill_dir, "SKILL.md")):
        with open(os.path.join(dest_skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(f"# {clean_id}\n\n## Description\nCustom user-provided skill for verification.\n")

    # 2. Update manifest
    manifest_data["skills"] = [s for s in manifest_data["skills"] if s["skill_id"] != clean_id]
    manifest_data["skills"].append({
        "skill_id": clean_id,
        "path": os.path.abspath(dest_skill_dir),
        "domain": domain,
        "source": "custom_user_input",
        "known_malicious": False
    })
    manifest_data["total_skills"] = len(manifest_data["skills"])
    manifest_data["benign_count"] = sum(1 for s in manifest_data["skills"] if not s.get("known_malicious", False))
    manifest_data["malicious_count"] = sum(1 for s in manifest_data["skills"] if s.get("known_malicious", False))

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    save_last_active_sample(sample_dir)

    return {
        "run_id": manifest_data.get("run_id"),
        "manifest_path": manifest_path,
        "sample_dir": sample_dir,
        "total_skills": manifest_data["total_skills"],
        "benign_count": manifest_data["benign_count"],
        "malicious_count": manifest_data["malicious_count"],
        "skills": manifest_data["skills"],
        "shortfall_warnings": []
    }


# ─────────────────────────────────────────────────────────────────────────────
# SCREEN 1: Sample Configuration
# ─────────────────────────────────────────────────────────────────────────────
st.header("1. Sample Configuration")

tab_sampler, tab_custom, tab_history = st.tabs([
    "🎲 Dynamic Sampler (Autonomous Agent)",
    "➕ Ingest & Test Custom Skill",
    "📂 Browse & Resume Past Runs"
])

# ── TAB 1: Dynamic Agent Sampler ──
with tab_sampler:
    st.markdown("Sample from **11,000+ GitSkills** and **MalSkillBench** with configurable ratios (up to **1,000 skills**).")

    # Key-Only (OpenAI / Gemini) Filter Toggle
    key_only_filter_enabled = st.checkbox(
        "Key-only filter (OpenAI / Gemini)",
        value=False,
        help="Restricts sample exclusively to skills whose sole external requirement is an OpenAI or Gemini API key (no other required secrets, databases, or third-party services)."
    )

    if key_only_filter_enabled:
        st.info("ℹ️ **Key-Only Mode Active:** Only benign skills requiring solely an OpenAI or Gemini API key are eligible. Benign/malicious ratio logic does not apply.")

        # Host environment key verification
        openai_present = bool(os.getenv("OPENAI_API_KEY"))
        gemini_present = bool(os.getenv("GEMINI_API_KEY"))
        col_k1, col_k2 = st.columns(2)
        with col_k1:
            if openai_present:
                st.success("🟢 `OPENAI_API_KEY`: Set on host")
            else:
                st.warning("⚠️ `OPENAI_API_KEY`: Missing on host")
        with col_k2:
            if gemini_present:
                st.success("🟢 `GEMINI_API_KEY`: Set on host")
            else:
                st.warning("⚠️ `GEMINI_API_KEY`: Missing on host")

        col_ko1, col_ko2, col_ko3 = st.columns([1.2, 1, 1])
        with col_ko1:
            allowed_keys_sel = st.selectbox(
                "Allowed API Key Provider:",
                options=["either", "openai", "gemini"],
                index=0,
                help="Select which provider API keys qualify skills for inclusion."
            )
        with col_ko2:
            ko_size = st.number_input(
                "Sample Size:",
                min_value=1,
                max_value=200,
                value=40,
                step=5,
                help="Target number of key-only skills to sample (default: 40; if pool is smaller, all will be sampled)."
            )
        with col_ko3:
            ko_seed = st.number_input(
                "Random Seed:",
                min_value=0,
                max_value=999999,
                value=42,
                step=1,
                help="Deterministic random seed."
            )

        if allowed_keys_sel == "openai" and not openai_present:
            st.error("⚠️ Selected provider is 'openai', but `OPENAI_API_KEY` is not set on the host!")
        elif allowed_keys_sel == "gemini" and not gemini_present:
            st.error("⚠️ Selected provider is 'gemini', but `GEMINI_API_KEY` is not set on the host!")
        elif allowed_keys_sel == "either" and not (openai_present or gemini_present):
            st.error("⚠️ Selected provider is 'either', but neither `OPENAI_API_KEY` nor `GEMINI_API_KEY` is set on the host!")

        # Pool metrics & exclusion report if filter_report.csv is available
        report_file = os.path.join("analysis", "filter_report.csv")
        if os.path.exists(report_file):
            try:
                import pandas as pd
                df_rep = pd.read_csv(report_file)
                n_pool = len(df_rep)
                n_eligible = len(df_rep[df_rep["eligible"] == True])
                col_m1, col_m2 = st.columns(2)
                col_m1.metric("Candidate Pool Size", f"{n_pool:,}")
                col_m2.metric("Eligible Key-Only Skills", f"{n_eligible:,}")

                with st.expander("📊 Candidate Pool Exclusion Reasons Breakdown", expanded=False):
                    reasons_list = []
                    for r in df_rep[df_rep["eligible"] == False]["exclusion_reason"].dropna():
                        for part in str(r).split("; "):
                            reasons_list.append(part.split("(")[0])
                    reason_counts = pd.Series(reasons_list).value_counts().reset_index()
                    reason_counts.columns = ["Exclusion Reason", "Candidate Count"]
                    st.dataframe(reason_counts, use_container_width=True)

                with open(report_file, "rb") as f_rep:
                    st.download_button(
                        label="📥 Download filter_report.csv",
                        data=f_rep,
                        file_name="filter_report.csv",
                        mime="text/csv"
                    )
            except Exception as e:
                st.caption(f"Note: Could not parse filter report: {e}")
        else:
            st.caption("ℹ️ Run `analysis/filter_openai_gemini_only.py` to generate the complete `analysis/filter_report.csv`.")

        if st.button("🎲 Build Key-Only Sample", type="primary"):
            with st.spinner("Filtering candidate pool and materializing key-only sample workspace..."):
                try:
                    sample_res = dynamic_agent_skill_fetch.fetch_sample(
                        total_count=int(ko_size),
                        seed=int(ko_seed),
                        key_only_filter=True,
                        allowed_keys=allowed_keys_sel
                    )
                    st.session_state.sample_data = sample_res
                    st.session_state.pipeline_report = None
                    save_last_active_sample(sample_res["sample_dir"])
                    st.success(
                        f"✅ Key-Only sample of {sample_res['total_skills']} skills generated! "
                        f"{' '.join(sample_res.get('shortfall_warnings', []))}"
                    )
                except Exception as e:
                    st.error(f"Key-only sampling failed: {str(e)}")

    else:
        with st.container():
            col1, col2, col3 = st.columns([1, 1, 1.2])

            with col1:
                total_count = st.number_input(
                    "How many skills to fetch?",
                    min_value=2,
                    max_value=1000,
                    value=20,
                    step=10,
                    help="Total count of candidate skills to sample and evaluate (Configurable from 2 up to 1,000 skills)."
                )

            # Automatic Adaptive Ratio based on sample size:
            # ≥500 skills: 95% GitSkills (benign) : 5% MalSkillBench (malicious)
            # <500 skills: 90% GitSkills (benign) : 10% MalSkillBench (malicious)
            n_total = int(total_count)
            if n_total >= 500:
                benign_ratio = 0.95
                expected_mal = round(n_total * 0.05)
                expected_benign = n_total - expected_mal
                ratio_desc = "95% GitSkills : 5% MalSkillBench"
            else:
                benign_ratio = 0.90
                expected_mal = round(n_total * 0.10)
                expected_benign = n_total - expected_mal
                ratio_desc = "90% GitSkills : 10% MalSkillBench"

            with col2:
                st.metric(
                    label="Auto Pool Ratio",
                    value=f"{expected_benign} Benign / {expected_mal} Malicious",
                    help=f"Adaptive distribution optimized for MalSkillBench pool size: {ratio_desc}."
                )
                st.caption(f"⚖️ **Distribution:** {ratio_desc}")

            with col3:
                require_standalone_low_api = st.checkbox(
                    "Runnable Python code (with low/no external APIs)",
                    value=True,
                    help="By default, every sample includes skills with runnable Python code (excluding instruction-only skills). Enable this filter to further restrict the sample to standalone runnable Python code with low/no external web or paid API calls."
                )

            with st.expander("Advanced: Domain Filter (Optional)", expanded=False):
                domain_options = ["data_processing", "file_system", "os_commands", "instruction_only"]
                selected_domains = st.multiselect(
                    "Filter to specific functional domains (leave blank for all):",
                    options=domain_options,
                    default=[]
                )

            if st.button("🎲 Generate Sample via DynamicAgentSkillFetch", type="primary"):
                with st.spinner("DynamicAgentSkillFetch agent inspecting source pools & validating integrity..."):
                    try:
                        sample_res = dynamic_agent_skill_fetch.fetch_sample(
                            total_count=int(total_count),
                            benign_ratio=benign_ratio,
                            exclude_external_api=require_standalone_low_api,
                            exclude_instruction_only=True,
                            require_standalone_code=require_standalone_low_api,
                            max_external_api_calls=1 if require_standalone_low_api else 999,
                            domain_filters=selected_domains if selected_domains else None
                        )
                        st.session_state.sample_data = sample_res
                        st.session_state.pipeline_report = None
                        save_last_active_sample(sample_res["sample_dir"])
                        st.success(
                            f"✅ Sample of {sample_res['total_skills']} skills generated "
                            f"({sample_res['benign_count']} benign / {sample_res['malicious_count']} malicious). "
                            f"{' '.join(sample_res.get('shortfall_warnings', []))}"
                        )
                    except Exception as e:
                        st.error(f"Sampling failed: {str(e)}")

# ── TAB 2: Custom Skill Ingestion ──
with tab_custom:
    st.markdown("Test your **own custom skill** against Level-1 Static Security and Level-2 Harbor Verification.")
    
    custom_method = st.radio(
        "Choose custom skill input mode:",
        options=["✍️ Interactive Editor (Write / Paste Code & Intent)", "📁 Local Folder Path on Disk", "📦 Upload ZIP Archive"],
        horizontal=True
    )

    col_c1, col_c2 = st.columns([1.5, 1])
    with col_c1:
        custom_id = st.text_input("Skill Identifier:", value="custom_my_skill", help="Alphanumeric ID for your skill")
    with col_c2:
        custom_domain = st.selectbox(
            "Primary Domain:",
            options=["data_processing", "file_system", "os_commands", "instruction_only"]
        )

    local_folder_input = None
    zip_upload_input = None
    skill_md_input = ""
    script_code_input = ""
    script_filename_input = "main.py"

    if custom_method == "📁 Local Folder Path on Disk":
        local_folder_input = st.text_input(
            "Absolute or Relative Directory Path:",
            placeholder="e.g. d:/research/my_custom_skill",
            help="Folder containing SKILL.md and optional scripts/ or config/ folders."
        )
    elif custom_method == "📦 Upload ZIP Archive":
        zip_upload_input = st.file_uploader(
            "Upload Skill ZIP Archive:",
            type=["zip"],
            help="ZIP package containing SKILL.md and optional python scripts."
        )
    else: # Interactive Editor
        skill_md_input = st.text_area(
            "SKILL.md (Declarative Intent, Tools, Boundaries):",
            value="""# My Custom Skill
## Description
This skill performs structured data analysis on user CSV files.

## Instructions
1. Reads input file from arguments.
2. Computes summary statistics and saves summary.txt.
""",
            height=150
        )
        col_s1, col_s2 = st.columns([1, 2])
        with col_s1:
            script_filename_input = st.text_input("Script Filename:", value="main.py")
        with col_s2:
            st.caption("Entry script to execute inside Harbor sandbox.")

        script_code_input = st.text_area(
            "Script Source Code (Python):",
            value="""import os
import sys

def main():
    print("Executing custom skill analysis...")
    with open("summary.txt", "w") as f:
        f.write("Analysis completed cleanly.")
    print("Done.")

if __name__ == "__main__":
    main()
""",
            height=160
        )

    col_btn_new, col_btn_append = st.columns([1, 1.2])
    with col_btn_new:
        if st.button("🚀 Load Custom Skill as New Sample", type="primary"):
            try:
                res = create_or_append_custom_skill(
                    skill_id=custom_id,
                    domain=custom_domain,
                    skill_md=skill_md_input,
                    code_content=script_code_input,
                    script_name=script_filename_input,
                    local_dir=local_folder_input,
                    zip_file=zip_upload_input,
                    append_to_existing=False
                )
                st.session_state.sample_data = res
                st.session_state.pipeline_report = None
                save_last_active_sample(res["sample_dir"])
                st.success(f"✅ Ingested `{custom_id}` as standalone test sample! Ready to run in Section 2.")
            except Exception as e:
                st.error(f"Failed to ingest custom skill: {str(e)}")

    with col_btn_append:
        if st.session_state.sample_data is not None:
            if st.button("➕ Append to Current Active Sample"):
                try:
                    res = create_or_append_custom_skill(
                        skill_id=custom_id,
                        domain=custom_domain,
                        skill_md=skill_md_input,
                        code_content=script_code_input,
                        script_name=script_filename_input,
                        local_dir=local_folder_input,
                        zip_file=zip_upload_input,
                        append_to_existing=True
                    )
                    st.session_state.sample_data = res
                    st.session_state.pipeline_report = None
                    save_last_active_sample(res["sample_dir"])
                    st.success(f"✅ Appended `{custom_id}` to active sample (Total now: {res['total_skills']} skills)!")
                except Exception as e:
                    st.error(f"Failed to append custom skill: {str(e)}")

# ── TAB 3: Browse & Resume Previous Runs ──
with tab_history:
    st.markdown("Revisit previous runs or resume interrupted tasks directly without losing progress.")
    all_past = scan_all_samples()
    if not all_past:
        st.info("No saved runs found in `dynamic_samples/` yet.")
    else:
        sample_options = {item["label"]: item for item in all_past}
        selected_label = st.selectbox(
            "Select a past sample or incomplete run from disk:",
            options=list(sample_options.keys()),
            help="Choose any previously generated sample or interrupted run stored in dynamic_samples/."
        )
        selected_item = sample_options[selected_label]

        m_c1, m_c2, m_c3, m_c4 = st.columns(4)
        m_c1.metric("Total Skills", selected_item["total_skills"])
        m_c2.metric("Evaluated Skills", selected_item["completed_skills"])
        m_c3.metric(
            "Status",
            "✅ Completed" if selected_item["is_completed"] else (
                f"⏳ Incomplete ({selected_item['completed_skills']}/{selected_item['total_skills']})"
                if selected_item["completed_skills"] > 0 else "⚪ Not Started"
            )
        )
        try:
            mod_time_str = datetime.fromtimestamp(selected_item["mtime"]).strftime("%Y-%m-%d %H:%M")
        except Exception:
            mod_time_str = "Unknown"
        m_c4.metric("Last Activity", mod_time_str)

        col_load_btn, col_view_btn, col_load_info = st.columns([1.5, 1.5, 2])
        with col_load_btn:
            if st.button("📥 Load & Activate This Run", type="primary", key="btn_load_history"):
                s_data, r_data = load_sample_dict(selected_item["sample_dir"])
                if s_data:
                    st.session_state.sample_data = s_data
                    st.session_state.pipeline_report = r_data if (r_data and len(r_data.get("results", [])) > 0) else None
                    save_last_active_sample(selected_item["sample_dir"])
                    st.success(f"✅ Loaded `{selected_item['dir_name']}`! Scroll down to inspect results or resume.")
                    st.rerun()

        with col_view_btn:
            has_report = selected_item.get("completed_skills", 0) > 0
            if st.button("📊 View Report (Screen 3)", type="secondary", disabled=not has_report, key="btn_view_history", help="Jump directly to Screen 3 Adjudication Report for this run"):
                s_data, r_data = load_sample_dict(selected_item["sample_dir"])
                if s_data and r_data:
                    st.session_state.sample_data = s_data
                    st.session_state.pipeline_report = r_data
                    save_last_active_sample(selected_item["sample_dir"])
                    st.rerun()

# Display Sampled/Ingested Skills
if st.session_state.sample_data:
    sample_res = st.session_state.sample_data
    skills_list = sample_res.get("skills", [])
    with st.expander(f"📋 View Configured Sample ({len(skills_list)} items)", expanded=False):
        df_sample = pd.DataFrame([
            {
                "Skill ID": s["skill_id"],
                "Domain": s["domain"],
                "Type": "Malicious" if s.get("known_malicious") else "Benign",
                "Source": s.get("source", "unknown")
            }
            for s in skills_list
        ])
        st.dataframe(df_sample, use_container_width=True)

# ─────────────────────────────────────────────────────────────────────────────
# SCREEN 2: Run Pipeline
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.sample_data:
    st.divider()
    st.header("2. Pipeline Execution")
    sample_res = st.session_state.sample_data
    manifest_path = sample_res["manifest_path"]
    sample_dir = sample_res["sample_dir"]
    report_file = os.path.join(sample_dir, "report.json")
    total_skills = sample_res["total_skills"]

    # Inspect checkpoint progress on disk
    already_done = 0
    cached_report = None
    if os.path.exists(report_file):
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                cached_report = json.load(f)
                already_done = len(cached_report.get("results", []))
        except Exception:
            already_done = 0

    is_fully_done = (already_done >= total_skills and total_skills > 0)
    is_partially_done = (already_done > 0 and already_done < total_skills)

    # Auto-load report for Screen 3 if cached report exists with results
    if cached_report and len(cached_report.get("results", [])) > 0:
        if st.session_state.pipeline_report is None or st.session_state.pipeline_report.get("run_id") != sample_res.get("run_id"):
            st.session_state.pipeline_report = cached_report

    col_info, col_ckpt = st.columns([1.5, 1.5])
    with col_info:
        st.info(f"Active Manifest: `{os.path.basename(sample_dir)}/manifest.json` ({total_skills} skills)")
    with col_ckpt:
        resume_mode = st.checkbox(
            "Resume from checkpoint (skip already verified skills)",
            value=True,
            help="When enabled, any skills already evaluated and saved to report.json are skipped, instantly resuming where execution stopped."
        )

    if is_partially_done and resume_mode:
        st.warning(
            f"⏳ **Incomplete Run Recovered:** `{already_done}/{total_skills}` skills already evaluated and checkpointed! "
            f"Verification will resume directly from skill **#{already_done + 1}** without repeating previous skills."
        )
    elif is_fully_done and resume_mode:
        st.success(f"✅ **Completed Run:** All `{total_skills}` skills are verified. Results are loaded in Screen 3 below.")

    col_btn_run, col_btn_view = st.columns([1.5, 1.5])

    if is_partially_done and resume_mode:
        btn_label = f"▶️ Resume Incomplete Pipeline ({already_done}/{total_skills} done)"
        btn_type = "primary"
    elif is_fully_done:
        btn_label = "🔄 Re-evaluate Sample (Force Refresh)"
        btn_type = "secondary"
    else:
        btn_label = "🚀 Run Verification Pipeline on This Sample"
        btn_type = "primary"

    with col_btn_run:
        run_clicked = st.button(btn_label, type=btn_type, disabled=st.session_state.is_running)

    with col_btn_view:
        if cached_report and len(cached_report.get("results", [])) > 0:
            if st.button("📊 View Current Results in Report (Screen 3)", help="Display existing adjudication charts and findings immediately."):
                st.session_state.pipeline_report = cached_report
                st.rerun()

    if run_clicked:
        st.session_state.is_running = True
        progress_bar = st.progress(0.0)
        status_text = st.empty()

        # If run is already fully complete, re-evaluating means a fresh execution pass
        actual_resume = resume_mode and not is_fully_done

        def on_start(curr, total, s_id):
            pct = (curr - 1) / total
            progress_bar.progress(pct)
            status_text.markdown(f"⏳ **Executing skill {curr}/{total}:** `{s_id}`...")

        def update_progress(curr, total, skill_res):
            pct = curr / total
            progress_bar.progress(pct)
            verdict_disp = skill_res.get("verdict") or skill_res.get("gating_status")
            status_text.markdown(f"✅ **Finished skill {curr}/{total}:** `{skill_res['skill_id']}` → `{verdict_disp}`")

        try:
            with st.spinner("Executing multi-agent verification pipeline..."):
                report = execute_manifest_pipeline(
                    manifest_path=manifest_path,
                    output_report_path=report_file,
                    force_refresh=True if not actual_resume else False,
                    resume=actual_resume,
                    on_skill_start=on_start,
                    on_skill_complete=update_progress
                )
                st.session_state.pipeline_report = report
                st.success("✅ Verification pipeline execution complete!")
        except Exception as e:
            st.error(f"Pipeline execution encountered an error: {str(e)}")
        finally:
            st.session_state.is_running = False

# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# SCREEN 3: Results & Adjudication Report
# ─────────────────────────────────────────────────────────────────────────────
if st.session_state.pipeline_report:
    st.divider()
    st.header("3. Adjudication & Security Report")
    report = st.session_state.pipeline_report
    results = report.get("results", [])
    total_skills = report.get("total_skills", len(results))

    CANONICAL_LABELS = [
        "Aligned",
        "Semantically_Divergent",
        "Undeclared_Behavior",
        "Unimplemented_Intent",
        "Blocked_Static_CRITICAL",
        "Inconclusive(HARNESS)",
        "Inconclusive(SKILL_CRASH)",
        "Inconclusive(INFRA)",
        "Inconclusive(LOW_COVERAGE)",
        "Inconclusive(NO_ENTRY)",
        "Inconclusive(NO_AGENT)",
        "Inconclusive(NO_TESTABLE_CONTRACTS)",
        "Inconclusive(TELEMETRY_GAP)",
    ]

    LEGACY_VERDICT_MAP = {
        "INCONCLUSIVE_HARNESS": "Inconclusive(HARNESS)",
        "INCONCLUSIVE_CRASH": "Inconclusive(SKILL_CRASH)",
        "INCONCLUSIVE_SKILL_CRASH": "Inconclusive(SKILL_CRASH)",
        "INCONCLUSIVE_INFRA": "Inconclusive(INFRA)",
        "INCONCLUSIVE_LOW_COVERAGE": "Inconclusive(LOW_COVERAGE)",
        "INCONCLUSIVE_NO_ACTION": "Inconclusive(LOW_COVERAGE)",
        "INCONCLUSIVE_NO_ENTRY": "Inconclusive(NO_ENTRY)",
        "INCONCLUSIVE_NO_AGENT": "Inconclusive(NO_AGENT)",
        "INCONCLUSIVE_NO_TESTABLE_CONTRACTS": "Inconclusive(NO_TESTABLE_CONTRACTS)",
        "INCONCLUSIVE_TELEMETRY_GAP": "Inconclusive(TELEMETRY_GAP)",
        "SKIPPED_LEVEL1_CRITICAL": "Blocked_Static_CRITICAL",
    }

    def _canonicalize_verdict(raw_v: Any, rec: Optional[Dict[str, Any]] = None) -> str:
        s_v = str(raw_v or "").strip()
        if s_v in CANONICAL_LABELS:
            return s_v
        if s_v in LEGACY_VERDICT_MAP:
            return LEGACY_VERDICT_MAP[s_v]
        if rec:
            if rec.get("level1_risk") == "CRITICAL" or rec.get("gating_status") == "SKIPPED_LEVEL1_CRITICAL":
                return "Blocked_Static_CRITICAL"
            nvr = str(rec.get("no_verdict_reason") or "").strip().upper()
            if nvr in ("HARNESS", "SKILL_CRASH", "INFRA", "LOW_COVERAGE", "NO_ENTRY", "NO_AGENT", "NO_TESTABLE_CONTRACTS", "TELEMETRY_GAP"):
                return f"Inconclusive({nvr})"
            g_st = str(rec.get("gating_status") or "").strip()
            if g_st in LEGACY_VERDICT_MAP:
                return LEGACY_VERDICT_MAP[g_st]
        return "Inconclusive(HARNESS)"

    label_counts: Dict[str, int] = {lbl: 0 for lbl in CANONICAL_LABELS}
    if results:
        for r in results:
            c_lbl = _canonicalize_verdict(r.get("verdict"), r)
            r["verdict"] = c_lbl
            label_counts[c_lbl] = label_counts.get(c_lbl, 0) + 1
    else:
        v_dist = report.get("verdict_distribution", {})
        for k, v in v_dist.items():
            c_lbl = _canonicalize_verdict(k)
            label_counts[c_lbl] = label_counts.get(c_lbl, 0) + int(v or 0)

    LABEL_HELP = {
        "Aligned": "Skill executed cleanly and satisfied declared behavioral contracts with zero violations.",
        "Semantically_Divergent": "Skill executed without security violations, but observed outputs contradicted contract postconditions.",
        "Undeclared_Behavior": "Skill violated a forbidden security invariant or performed undeclared file, network, or command actions.",
        "Unimplemented_Intent": "Skill reached a stub (e.g. pass/NotImplementedError) or failed to produce its declared postcondition effect.",
        "Blocked_Static_CRITICAL": "Blocked pre-execution at the Level-1 static security gate due to a CRITICAL threat signature.",
        "Inconclusive(HARNESS)": "Verdict withheld because CLI arguments, fixtures, or harness preconditions did not exercise the entry point.",
        "Inconclusive(SKILL_CRASH)": "Verdict withheld because the skill crashed with a non-zero runtime exception during execution.",
        "Inconclusive(INFRA)": "Verdict withheld due to container, timeout, OOM, or missing third-party package infrastructure errors.",
        "Inconclusive(LOW_COVERAGE)": "Verdict withheld because execution completed with zero violations but contract coverage was below threshold.",
        "Inconclusive(NO_ENTRY)": "Verdict withheld because no runnable script entry point existed in the skill package.",
        "Inconclusive(NO_AGENT)": "Verdict withheld because the skill is instruction-only (SKILL.md) and no live LLM agent key was configured.",
        "Inconclusive(NO_TESTABLE_CONTRACTS)": "Verdict withheld because all synthesized behavioral contracts were marked non-testable (zero testable contracts).",
        "Inconclusive(TELEMETRY_GAP)": "Verdict withheld because the agent produced textual advice without executable tool or command telemetry.",
    }

    # ── CANONICAL VERDICT METRIC CARDS (No Duplicate or Aliased Labels) ──
    st.markdown("#### ⚖️ Canonical Verdict & Security Label Counts")
    row1_cols = st.columns(6)
    row1_cols[0].metric("Total Skills", total_skills, help="Total candidate skills evaluated in this sample.")
    for idx, lbl in enumerate(CANONICAL_LABELS[:5], start=1):
        row1_cols[idx].metric(lbl, label_counts[lbl], help=LABEL_HELP.get(lbl, ""))

    row2_cols = st.columns(len(CANONICAL_LABELS[5:]))
    for idx, lbl in enumerate(CANONICAL_LABELS[5:]):
        row2_cols[idx].metric(lbl, label_counts[lbl], help=LABEL_HELP.get(lbl, ""))

    # ── FORMAL CONTRACT METRIC CARDS (Fix 5) ──
    st.markdown("#### 📜 Behavioral Contract Summary")
    c_m1, c_m2, c_m3 = st.columns(3)
    c_m1.metric("Total Contracts Synthesized", report.get("contracts_total", sum(int(r.get("contracts_total", 0) or 0) for r in results)))
    c_m2.metric("Testable Contracts", report.get("contracts_testable", sum(int(r.get("contracts_testable", 0) or 0) for r in results)))
    c_m3.metric("Non-Testable Contracts", report.get("contracts_non_testable", sum(int(r.get("contracts_non_testable", 0) or 0) for r in results)))

    # ── CANONICAL VERDICT DISTRIBUTION CHART & BREAKDOWN TABLE ──
    st.markdown("---")
    st.markdown("### 📊 Canonical Verdict Distribution")
    df_canonical = pd.DataFrame(
        [{"Label": lbl, "Count": label_counts[lbl]} for lbl in CANONICAL_LABELS]
    ).set_index("Label")
    st.bar_chart(df_canonical)

    st.markdown("#### 📋 Canonical Label Breakdown Table")
    breakdown_rows = [
        {
            "Label": "Total Skills",
            "Count": total_skills,
            "Share (%)": "100.0%" if total_skills > 0 else "0.0%",
            "Definition": "Total number of candidate skills evaluated in this verification run.",
        }
    ]
    for lbl in CANONICAL_LABELS:
        cnt = label_counts[lbl]
        pct_str = f"{round((cnt / total_skills) * 100, 1)}%" if total_skills > 0 else "0.0%"
        breakdown_rows.append(
            {
                "Label": lbl,
                "Count": cnt,
                "Share (%)": pct_str,
                "Definition": LABEL_HELP[lbl],
            }
        )
    st.dataframe(pd.DataFrame(breakdown_rows), use_container_width=True)

    # ── CONTAINER: Label & Verdict Taxonomy Guide ──
    with st.container():
        st.markdown("---")
        st.subheader("📖 Label & Verdict Taxonomy Guide (Canonical Labels)")
        st.markdown(
            "Every skill in the report receives **exactly one** of the following 11 canonical labels (no duplicate or aliased label names are used):"
        )

        st.markdown(
            r"""
            - **`Aligned`**: Verified that the skill executed cleanly and fulfilled its declared behavioral contracts (coverage $\ge 0.50$) with zero security invariant or frame axiom violations.
            - **`Semantically_Divergent`**: The skill executed without security violations, but its actual outputs or side-effects contradicted the declared contract postconditions.
            - **`Undeclared_Behavior`**: The skill violated a forbidden security invariant or frame axiom at runtime (e.g., unauthorized network egress, credential/canary file access, persistence write, or undeclared command execution).
            - **`Unimplemented_Intent`**: The skill entry point is an unimplemented stub (`pass` / `NotImplementedError`) or completed without producing the declared postcondition effect.
            - **`Blocked_Static_CRITICAL`**: Pre-execution Level-1 static AST/regex gate detected a critical threat signature (e.g., reverse shell, raw C2 IP, destructive command) and blocked sandbox execution.
            - **`Inconclusive(HARNESS)`**: Verdict withheld because the test harness arguments, input fixtures, or preconditions failed to invoke the skill logic cleanly (e.g., CLI usage exit code 2 or missing input fixture).
            - **`Inconclusive(SKILL_CRASH)`**: Verdict withheld because the skill reached its logic and crashed with an unhandled runtime exception (non-zero exit code) and zero security violations.
            - **`Inconclusive(INFRA)`**: Verdict withheld due to an environment or infrastructure failure (e.g., missing third-party library `ModuleNotFoundError`, container timeout `124`, or OOM `137`).
            - **`Inconclusive(LOW_COVERAGE)`**: Verdict withheld because the skill ran without crashing or violating invariants, but fewer than 50% of synthesized behavioral contracts were exercised and verified.
            - **`Inconclusive(NO_ENTRY)`**: Verdict withheld because no runnable script entry point (`.py`, `.sh`, `.js`, `.mjs`) could be found in the skill directory.
            - **`Inconclusive(NO_AGENT)`**: Verdict withheld because the skill is instruction-only (`SKILL.md` with no scripts) and no external LLM agent API key (`ANTHROPIC_API_KEY`) was provided for trajectory execution.
            """
        )
        st.markdown("---")

    # ── MULTI-FILTER SEARCHABLE RESULTS TABLE (TASK 2) ──
    st.subheader("Per-Skill Verification Results (Multi-Filter Table)")
    df_results = pd.DataFrame([
        {
            "Skill ID": r["skill_id"],
            "Domain": r["domain"],
            "Provenance": "Malicious" if r.get("known_malicious") else "Benign",
            "Run Status": r.get("run_status", "UNKNOWN"),
            "DTC Coverage": f"{round(float(r.get('dtc', r.get('coverage_score', 0.0)) or 0.0) * 100, 1)}%",
            "CSR_C Satisfaction": f"{round(float(r.get('csr_c', 0.0) or 0.0) * 100, 1)}%",
            "Level-1 Risk": r.get("level1_risk", "LOW"),
            "Gating Status": r.get("gating_status", "UNKNOWN"),
            "Backend": r.get("backend", "harbor_docker"),
            "Valid for Paper": "✅ Yes" if r.get("valid_for_paper", True) else "❌ No",
            "Verdict": r.get("verdict") or "null",
            "Sublabel / Error": r.get("execution_error_sublabel") or ("Blocked CRITICAL" if r.get("level1_risk") == "CRITICAL" else "None")
        }
        for r in results
    ])

    fcol1, fcol2, fcol3, fcol4 = st.columns(4)
    with fcol1:
        unique_verdicts = ["All"] + sorted(list(set(df_results["Verdict"].tolist())))
        sel_verdict = st.selectbox("Filter by Verdict:", unique_verdicts)
    with fcol2:
        unique_domains = ["All"] + sorted(list(set(df_results["Domain"].tolist())))
        sel_domain = st.selectbox("Filter by Domain:", unique_domains)
    with fcol3:
        unique_prov = ["All"] + sorted(list(set(df_results["Provenance"].tolist())))
        sel_prov = st.selectbox("Filter by Provenance:", unique_prov)
    with fcol4:
        unique_rstatus = ["All"] + sorted(list(set(df_results["Run Status"].tolist())))
        sel_rstatus = st.selectbox("Filter by Run Status:", unique_rstatus)

    filtered_df = df_results
    if sel_verdict != "All":
        filtered_df = filtered_df[filtered_df["Verdict"] == sel_verdict]
    if sel_domain != "All":
        filtered_df = filtered_df[filtered_df["Domain"] == sel_domain]
    if sel_prov != "All":
        filtered_df = filtered_df[filtered_df["Provenance"] == sel_prov]
    if sel_rstatus != "All":
        filtered_df = filtered_df[filtered_df["Run Status"] == sel_rstatus]

    st.dataframe(filtered_df, use_container_width=True)

    # ── RUN-LEVEL LABEL DISTRIBUTION SANITY WARNING ──
    sanity_warn = report.get("label_sanity_warning")
    if sanity_warn:
        st.warning(f"⚠️ **{sanity_warn.get('warning', 'Label Distribution Sanity Warning')}**")
        top_evs = sanity_warn.get("top_evidence_types", [])
        if top_evs:
            st.markdown("**Top Evidence Types contributing to dominant label:**")
            for tev in top_evs:
                st.markdown(f"- `{tev}`")

    # ── DETAILED EVIDENCE & REASONING INSPECTOR ──
    st.subheader("Detailed Evidence & Reason Inspection")
    selected_skill = st.selectbox(
        "Select a skill to inspect full Level-1, Level-2, and execution traces:",
        options=[r["skill_id"] for r in results]
    )

    if selected_skill:
        skill_detail = next((r for r in results if r["skill_id"] == selected_skill), None)
        if skill_detail:
            # ─────────────────────────────────────────────────────────────
            # 1. Header: skill id, verdict badge, one-line plain-English reason
            # ─────────────────────────────────────────────────────────────
            v_val = skill_detail.get("verdict") or "Inconclusive"
            badge_color = {
                "Aligned": "green",
                "Semantically_Divergent": "orange",
                "Undeclared_Behavior": "red",
                "Unimplemented_Intent": "orange",
                "Blocked_Static_CRITICAL": "red",
            }.get(v_val, "gray")

            one_line_reason = (
                skill_detail.get("level2_reason")
                or (skill_detail.get("explanation") or {}).get("headline")
                or "Evaluation complete."
            )

            st.markdown(f"### `{selected_skill}` :{badge_color}[{v_val}]")
            st.markdown(f"**Reason:** {one_line_reason}")
            fcls = skill_detail.get("failure_class") or (skill_detail.get("prediction") or {}).get("failure_class")
            if fcls:
                st.markdown(f"**failure_class:** `{fcls}`")
            ex_reasons = [
                f"{cs.get('contract_id')}: {cs.get('exercise_reason')}"
                for cs in (skill_detail.get("contract_status") or [])
                if isinstance(cs, dict) and cs.get("exercise_reason")
            ]
            if ex_reasons:
                st.markdown("**exercise_reason:** " + "; ".join(ex_reasons[:8]))

            # ─────────────────────────────────────────────────────────────
            # 2. "Findings" table: One row per ROOT CAUSE
            # ─────────────────────────────────────────────────────────────
            st.markdown("---")
            st.markdown("#### 🔍 Verification Findings (Grouped by Root Cause)")

            violations = skill_detail.get("violations") or []
            attributions = skill_detail.get("attribution") or []
            contract_status = skill_detail.get("contract_status") or []
            behavior_units = {bu.get("id"): bu for bu in skill_detail.get("behavior_units") or []}

            finding_groups = {}

            # Process violations (Undeclared Behavior)
            for v in violations:
                b_id = v.get("behavior_unit_id")
                bu = behavior_units.get(b_id, {})
                target = bu.get("target") or v.get("detail") or ""

                # Derive path prefix
                path_prefix = "N/A"
                if target:
                    if "/" in target:
                        p_parts = [p for p in target.split("/") if p]
                        path_prefix = "/" + "/".join(p_parts[:2]) if len(p_parts) >= 2 else ("/" + p_parts[0] if p_parts else target)
                    else:
                        path_prefix = target.split()[0] if target.split() else target

                # Find attribution
                matching_attr = next(
                    (a for a in attributions if isinstance(a, dict) and (a.get("behavior_unit_id") == b_id or a.get("rule_id") == v.get("rule_id"))),
                    None
                )
                code_sites = (matching_attr.get("code_sites") or []) if isinstance(matching_attr, dict) else []
                intent_refs = (matching_attr.get("intent_refs") or []) if isinstance(matching_attr, dict) else []

                # Filter out internal repo files
                valid_intents = [
                    ir for ir in intent_refs
                    if isinstance(ir, dict) and ir.get("file") and not str(ir.get("file")).startswith("src/") and "system_baseline" not in str(ir.get("file"))
                ]

                actor_call_chain = []
                if code_sites and isinstance(code_sites[-1], dict):
                    actor = code_sites[-1]
                    code_site_str = f"{actor.get('file')}:{actor.get('line')} ({actor.get('qualname')})"
                    code_site_key = code_site_str
                    actor_call_chain = list(actor.get("call_chain") or [])
                elif bu.get("via_system_tool") or (bu.get("exec_chain") and len(bu.get("exec_chain")) > 1):
                    chain = bu.get("exec_chain") or []
                    tool_name = chain[-1] if chain else "system tool"
                    code_site_str = f"no skill code site; performed by {tool_name}"
                    code_site_key = f"system_tool_{tool_name}"
                else:
                    code_site_str = "no skill code site (unattributed)"
                    code_site_key = "unattributed"

                if valid_intents:
                    first_i = valid_intents[0]
                    quote_snip = _truncate_words(first_i.get("quote") or "", 50)
                    declared_intent_str = f"{first_i.get('file')}:{first_i.get('line_start')} (\"{quote_snip}\")"
                else:
                    declared_intent_str = "No declaration covers this"

                rule_id = v.get("rule_id", "UNDECLARED")
                g_key = ("Undeclared_Behavior", rule_id, path_prefix, code_site_key)

                if g_key not in finding_groups:
                    finding_groups[g_key] = {
                        "Type": "Undeclared_Behavior",
                        "Rule": rule_id,
                        "Where in skill (file:line, function)": code_site_str,
                        "Call chain": " -> ".join(actor_call_chain) if actor_call_chain else "direct invocation",
                        "Declared intent": declared_intent_str,
                        "Evidence": f"{v.get('evidence_ref', '')} ({b_id})" if b_id else v.get("evidence_ref", ""),
                        "Events": 0,
                        "target": target,
                        "detail": v.get("detail", ""),
                        "raw_items": [],
                        "attr": matching_attr,
                    }
                finding_groups[g_key]["Events"] += 1
                finding_groups[g_key]["raw_items"].append({
                    "unit_id": b_id,
                    "target": target,
                    "evidence_ref": v.get("evidence_ref"),
                    "detail": v.get("detail"),
                })

            # Process Unimplemented Intent
            for cs in contract_status:
                if cs.get("status") in ("STUB", "EFFECT_ABSENT"):
                    c_id = cs.get("contract_id", "")
                    matching_attr = next((a for a in attributions if isinstance(a, dict) and a.get("contract_id") == c_id), None)
                    intent_refs = (matching_attr.get("intent_refs") or []) if isinstance(matching_attr, dict) else []
                    valid_intents = [
                        ir for ir in intent_refs
                        if isinstance(ir, dict) and ir.get("file") and not str(ir.get("file")).startswith("src/") and "system_baseline" not in str(ir.get("file"))
                    ]
                    if valid_intents:
                        first_i = valid_intents[0]
                        quote_snip = _truncate_words(first_i.get("quote") or "", 50)
                        declared_intent_str = f"{first_i.get('file')}:{first_i.get('line_start')} (\"{quote_snip}\")"
                    else:
                        declared_intent_str = "No declaration covers this"

                    absence = (matching_attr.get("absence") or {}) if isinstance(matching_attr, dict) else {}
                    where_str = "Stub/absent effect"
                    if isinstance(absence, dict) and absence.get("searched_files"):
                        where_str = f"Missing in {absence['searched_files'][0]}"
                    elif isinstance(absence, dict) and absence.get("candidate_symbols"):
                        where_str = f"Non-invoked: {absence['candidate_symbols'][0]}"

                    g_key = ("Unimplemented_Intent", c_id, "contract", c_id)
                    if g_key not in finding_groups:
                        finding_groups[g_key] = {
                            "Type": "Unimplemented_Intent",
                            "Rule": c_id,
                            "Where in skill (file:line, function)": where_str,
                            "Declared intent": declared_intent_str,
                            "Evidence": "; ".join(cs.get("cited_unit_ids", [])) or "None",
                            "Events": 1,
                            "target": cs.get("reason", ""),
                            "detail": cs.get("reason", ""),
                            "raw_items": [cs],
                            "absence": absence,
                            "contract_id": c_id,
                        }

            # Process Semantic Divergence
            for cs in contract_status:
                if cs.get("status") == "CONTRADICTED":
                    c_id = cs.get("contract_id", "")
                    matching_attr = next((a for a in attributions if isinstance(a, dict) and a.get("contract_id") == c_id), None)
                    intent_refs = (matching_attr.get("intent_refs") or []) if isinstance(matching_attr, dict) else []
                    valid_intents = [
                        ir for ir in intent_refs
                        if isinstance(ir, dict) and ir.get("file") and not str(ir.get("file")).startswith("src/") and "system_baseline" not in str(ir.get("file"))
                    ]
                    if valid_intents:
                        first_i = valid_intents[0]
                        quote_snip = _truncate_words(first_i.get("quote") or "", 50)
                        declared_intent_str = f"{first_i.get('file')}:{first_i.get('line_start')} (\"{quote_snip}\")"
                    else:
                        declared_intent_str = "No declaration covers this"

                    code_sites = (matching_attr.get("code_sites") or []) if isinstance(matching_attr, dict) else []
                    diverge_call_chain = []
                    if code_sites and isinstance(code_sites[-1], dict):
                        actor = code_sites[-1]
                        where_str = f"{actor.get('file')}:{actor.get('line')} ({actor.get('qualname')})"
                        diverge_call_chain = list(actor.get("call_chain") or [])
                    else:
                        where_str = "Runtime output divergence"

                    g_key = ("Semantically_Divergent", c_id, "contract", c_id)
                    if g_key not in finding_groups:
                        finding_groups[g_key] = {
                            "Type": "Semantically_Divergent",
                            "Rule": c_id,
                            "Where in skill (file:line, function)": where_str,
                            "Call chain": " -> ".join(diverge_call_chain) if diverge_call_chain else "direct invocation",
                            "Declared intent": declared_intent_str,
                            "Evidence": "; ".join(cs.get("cited_unit_ids", [])) or "telemetry",
                            "Events": 1,
                            "target": cs.get("reason", ""),
                            "detail": cs.get("reason", ""),
                            "raw_items": [cs],
                            "contract_id": c_id,
                        }

            findings_list = list(finding_groups.values())

            if not findings_list:
                st.success("✅ **Zero Violations or Divergences Found:** Skill executed within declared frame axioms and satisfied behavioral postconditions.")
            else:
                table_cols = [
                    "Type",
                    "Rule",
                    "Where in skill (file:line, function)",
                    "Call chain",
                    "Declared intent",
                    "Evidence",
                    "Events",
                ]
                df_findings = pd.DataFrame([
                    {col: f.get(col, "") for col in table_cols}
                    for f in findings_list
                ])

                if len(df_findings) <= 5:
                    st.dataframe(df_findings, use_container_width=True, hide_index=True)
                else:
                    st.dataframe(df_findings.iloc[:5], use_container_width=True, hide_index=True)
                    with st.expander(f"📋 Show all findings ({len(df_findings)} total)", expanded=False):
                        st.dataframe(df_findings, use_container_width=True, hide_index=True)

                with st.expander("🔍 View Raw Grouped Telemetry Events by Root Cause", expanded=False):
                    for idx, fg in enumerate(findings_list, start=1):
                        st.markdown(f"**Group #{idx}: `{fg['Type']}` — `{fg['Rule']}` ({fg['Events']} event(s))**")
                        st.dataframe(pd.DataFrame(fg["raw_items"]), use_container_width=True, hide_index=True)

            # ─────────────────────────────────────────────────────────────
            # 3. Type-specific detail card per finding
            # ─────────────────────────────────────────────────────────────
            if findings_list:
                st.markdown("---")
                st.markdown("#### 🔬 Finding Details & Causal Explanations")

                def _render_finding_card(idx, fg):
                    ftype = fg["Type"]
                    with st.container():
                        if ftype == "Undeclared_Behavior":
                            st.markdown(f"**Finding #{idx} [Undeclared Behavior]: `{fg['Rule']}`**")
                            st.markdown(f"- **What was touched:** `{fg['target']}`")
                            st.markdown(f"- **Root Sink Code Site:** `{fg['Where in skill (file:line, function)']}`")
                            st.markdown(f"- **Full Call Chain:** `{fg.get('Call chain', 'direct invocation')}`")
                            st.markdown(f"- **Rule:** `{fg['Rule']}`")
                            st.markdown(f"- **Why undeclared:** Target `{fg['target']}` is not declared in SKILL.md frame axioms ({fg['Declared intent']}).")
                        elif ftype == "Unimplemented_Intent":
                            st.markdown(f"**Finding #{idx} [Unimplemented Intent]: Contract `{fg['Rule']}`**")
                            st.markdown(f"- **Contract & SKILL.md claim:** `{fg['Rule']}` ({fg['Declared intent']})")
                            st.markdown(f"- **Absence Detail:** Where in code the stub/missing effect is: `{fg['Where in skill (file:line, function)']}`")
                            abs_info = fg.get("absence")
                            if isinstance(abs_info, dict):
                                if abs_info.get("expected_artifact_or_effect"):
                                    st.markdown(f"- **Expected Effect:** {abs_info.get('expected_artifact_or_effect')}")
                                if abs_info.get("candidate_symbols"):
                                    st.markdown(f"- **Candidate Symbols:** {', '.join(f'`{s}`' for s in abs_info.get('candidate_symbols', []))}")
                        elif ftype == "Semantically_Divergent":
                            st.markdown(f"**Finding #{idx} [Semantic Divergence]: Contract `{fg['Rule']}`**")
                            st.markdown(f"- **Claim line:** `{fg['Declared intent']}`")
                            st.markdown(f"- **Expected vs Observed:** {fg['detail']}")
                            st.markdown(f"- **Divergence location:** `{fg['Where in skill (file:line, function)']}`")
                            st.markdown(f"- **Full Call Chain:** `{fg.get('Call chain', 'direct invocation')}`")
                        st.markdown("")

                if len(findings_list) <= 1:
                    _render_finding_card(1, findings_list[0])
                else:
                    # Show the first finding directly on the initial screen
                    _render_finding_card(1, findings_list[0])
                    # Group remaining findings inside an expander so they don't clutter the page
                    with st.expander(f"📋 Show all detailed findings ({len(findings_list)} total)", expanded=False):
                        for idx, fg in enumerate(findings_list[1:], start=2):
                            _render_finding_card(idx, fg)

            # ─────────────────────────────────────────────────────────────
            # 4. Short "Limitations" line auto-filled from facts (Hide if empty)
            # ─────────────────────────────────────────────────────────────
            lim_list = []
            dtc = float(skill_detail.get("dtc", skill_detail.get("coverage_score", 0.0)) or 0.0)
            if dtc < 1.0 and dtc > 0.0:
                lim_list.append(f"Low test coverage (DTC = {round(dtc * 100, 1)}%)")
            elif dtc == 0.0:
                lim_list.append("Zero test coverage (DTC = 0.0%)")

            unattr_events = sum(
                1 for fg in findings_list
                if "no skill code site" in fg.get("Where in skill (file:line, function)", "")
            )
            if unattr_events > 0:
                lim_list.append(f"{unattr_events} finding group(s) without verified skill code site")

            if skill_detail.get("gating_status") == "INCONCLUSIVE_NO_AGENT" or skill_detail.get("no_verdict_reason") == "NO_AGENT":
                lim_list.append("Instruction-only skill evaluated without external agent credentials")

            non_testable_cnt = int(skill_detail.get("contracts_non_testable", 0) or 0)
            if non_testable_cnt > 0:
                lim_list.append(f"{non_testable_cnt} contract(s) marked non-testable")

            if lim_list:
                st.markdown("---")
                st.info(f"⚠️ **Limitations:** {'; '.join(lim_list)}")

            # ─────────────────────────────────────────────────────────────
            # 5. Everything else in collapsed expanders BELOW
            # ─────────────────────────────────────────────────────────────
            st.markdown("---")

            # Formatted Explanation (no raw dict)
            expl = skill_detail.get("explanation")
            if expl and isinstance(expl, dict):
                with st.expander("💡 Grounded Adjudication Explanation (Formatted)", expanded=False):
                    if expl.get("headline"):
                        st.markdown(f"**Headline:** {expl['headline']}")
                    if expl.get("summary"):
                        st.markdown(f"**Summary:** {expl['summary']}")
                    if expl.get("llm_narrative"):
                        st.markdown(f"**LLM Narrative:**\n\n{expl['llm_narrative']}")
                    if expl.get("execution_error_note"):
                        st.warning(f"Execution Error Note: {expl['execution_error_note']}")

            # Formal Contracts
            c_verdicts = skill_detail.get("contract_verdicts") or []
            c_total = skill_detail.get("contracts_total", len(c_verdicts))
            c_testable = skill_detail.get("contracts_testable", sum(1 for c in c_verdicts if c.get("testable", True)))
            c_non_testable = skill_detail.get("contracts_non_testable", c_total - c_testable)

            with st.expander(f"📜 Formal Contracts & Coverage ({c_total} total, {c_testable} testable)", expanded=False):
                m1, m2, m3, m4, m5 = st.columns(5)
                m1.metric("Total Contracts", c_total)
                m2.metric("Testable", c_testable)
                m3.metric("Non-Testable", c_non_testable)
                m4.metric("DTC Coverage", f"{round(dtc * 100, 1)}%")
                m5.metric("CSR-C Satisfaction", f"{round(float(skill_detail.get('csr_c', 0.0) or 0.0) * 100, 1)}%")

                if c_verdicts:
                    cv_df = pd.DataFrame([
                        {
                            "Contract ID": cv.get("contract_id"),
                            "Verdict": cv.get("verdict"),
                            "Status": cv.get("status", cv.get("verdict")),
                            "Exercised": "✅ Yes" if cv.get("exercised") else "❌ No",
                            "Evidence / Reason": "; ".join(cv.get("violation_evidence", [])) if cv.get("violation_evidence") else "Passed"
                        }
                        for cv in c_verdicts
                    ])
                    st.dataframe(cv_df, use_container_width=True)

            # Agent Coordination Timeline
            agent_msgs = skill_detail.get("agent_messages") or []
            with st.expander(f"🤖 Multi-Agent Coordination Timeline ({len(agent_msgs)} steps)", expanded=False):
                if not agent_msgs:
                    st.caption("No agent messages recorded.")
                for m_idx, msg in enumerate(agent_msgs, start=1):
                    ag_name = (msg.get("agent") or "agent").upper()
                    round_num = msg.get("round", 0)
                    act = msg.get("chosen_tool") or msg.get("action") or "step"
                    mode_val = msg.get("mode", "deterministic")
                    model_val = msg.get("model") or "None"
                    hash_val = (msg.get("skill_version_hash") or "")[:8]
                    lat = msg.get("latency_ms", 0)

                    st.markdown(f"**Step {m_idx} — `{ag_name}` (Round {round_num}): `{act}`**")
                    st.caption(f"Mode: `{mode_val}` | Model: `{model_val}` | Skill Hash: `{hash_val}` | Latency: `{lat}ms`")
                    if msg.get("fallback_reason"):
                        st.warning(f"Fallback Reason: {msg['fallback_reason']}")
                    if msg.get("reason"):
                        st.markdown(f"*Rationale:* {msg['reason']}")
                    if msg.get("directive"):
                        st.info(f"Directive: {msg['directive']}")
                    st.markdown("---")

            # Raw Telemetry & Behavior Units
            b_units = skill_detail.get("behavior_units") or []
            with st.expander(f"🔬 Raw Telemetry & Behavior Units ({len(b_units)} units)", expanded=False):
                st.markdown(f"**Run Status:** `{skill_detail.get('run_status')}`")
                if skill_detail.get("execution_error_sublabel"):
                    st.markdown(f"**Sublabel:** `{skill_detail.get('execution_error_sublabel')}`")
                if b_units:
                    df_bu = pd.DataFrame([
                        {
                            "ID": bu.get("id"),
                            "Kind": bu.get("kind"),
                            "Target": bu.get("target"),
                            "PID": str(bu.get("pid") if bu.get("pid") is not None else "N/A"),
                            "System Tool": "✅ Yes" if bu.get("via_system_tool") else "No",
                            "Exec Chain": " ➔ ".join(bu.get("exec_chain", [])) if bu.get("exec_chain") else "None",
                            "Ref": bu.get("evidence_ref"),
                        }
                        for bu in b_units
                    ])
                    st.dataframe(df_bu, use_container_width=True)

            # Level-1 Static Analysis
            with st.expander("🛡️ Level-1 Static Security Analysis", expanded=False):
                st.markdown(f"**Risk Level:** `{skill_detail.get('level1_risk')}`")
                st.markdown(f"**Reason:** {skill_detail.get('level1_reason')}")
                st.markdown(f"**Gating Status:** `{skill_detail.get('gating_status')}`")

    # Export Download Button
    st.divider()
    report_json_str = json.dumps(report, indent=2)
    st.download_button(
        label="📥 Download Full Report JSON",
        data=report_json_str,
        file_name=f"verification_report_{report.get('run_id', 'dynamic')}.json",
        mime="application/json"
    )


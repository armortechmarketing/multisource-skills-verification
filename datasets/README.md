# Datasets Guide & Setup Instructions

The raw datasets (`gitskills_raw/` and `MalSkillBench/`) are excluded from Git version control via `.gitignore` due to file size constraints (~277 MB SQLite database) and security policies (active exploit payloads).

Follow the instructions below to clone and prepare the datasets directly in your repository root.

---

## 1. `gitskills_raw/` (Benign Skills Dataset)

* **Source Repository:** [giuseppedestefanis/gitskills-sample](https://github.com/giuseppedestefanis/gitskills-sample)
* **Contents:** `agent_skills_sample.zip` containing `agent_skills_sample.db` (~277 MB SQLite database of 13,000+ real-world agent skills).

### Clone & Unzip:
```bash
# 1. Clone into the gitskills_raw directory
git clone https://github.com/giuseppedestefanis/gitskills-sample.git gitskills_raw
```

```bash
# 2. CRITICAL STEP: Extract the SQLite database file
# On Linux / macOS:
cd gitskills_raw && unzip agent_skills_sample.zip && cd ..

# On Windows (PowerShell):
Expand-Archive -Path .\gitskills_raw\agent_skills_sample.zip -DestinationPath .\gitskills_raw\ -Force

# On Windows (Command Prompt):
tar -xf gitskills_raw\agent_skills_sample.zip -C gitskills_raw
```

> [!IMPORTANT]
> The database file `gitskills_raw/agent_skills_sample.db` **must** exist for `DynamicAgentSkillFetch` and the benchmark sampler to query benign skills.

---

## 2. `MalSkillBench/` (Malicious Skills Dataset)

* **Source Repository:** [lxyeternal/MalSkillBench](https://github.com/lxyeternal/MalSkillBench)
* **Contents:** Labeled malicious skills covering 15 attack vectors under `Dataset/Skills/malware/`.

### Clone:
```bash
# Clone into the MalSkillBench directory
git clone https://github.com/lxyeternal/MalSkillBench.git MalSkillBench
```

> [!WARNING]
> Contains real-world malware payloads, reverse shells, and persistence scripts. Do not execute scripts directly on the host machine without sandboxing.

---

## 3. Directory Layout Verification

After completing these setup steps, verify your directory structure matches:

```
d:/research/ (project root)
├── gitskills_raw/
│   ├── agent_skills_sample.db   <-- REQUIRED: extracted SQLite DB (~277 MB)
│   ├── agent_skills_sample.zip
│   └── README.md
├── MalSkillBench/
│   └── Dataset/
│       └── Skills/
│           └── malware/         <-- REQUIRED: malicious skill folders
```

Once both folders are present, you can run the dynamic sampling pipeline and benchmarks seamlessly.

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None


DEFAULT_AGENT_SKILLS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "agent_skills")
)


def parse_frontmatter_and_content(markdown_text: str) -> Tuple[Dict[str, Any], str]:
    """Parses frontmatter (YAML) and markdown content from a SKILL.md file string."""
    metadata: Dict[str, Any] = {}
    content = markdown_text

    pattern = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)
    match = pattern.match(markdown_text)
    if match:
        fm_text = match.group(1)
        content = match.group(2).strip()
        if yaml is not None:
            try:
                parsed = yaml.safe_load(fm_text)
                if isinstance(parsed, dict):
                    metadata = parsed
            except Exception:
                metadata = {}
        else:
            # Fallback basic key-value parser
            for line in fm_text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and ":" in line:
                    k, v = line.split(":", 1)
                    metadata[k.strip()] = v.strip()

    return metadata, content


def list_agent_skills(base_dir: Optional[str] = None) -> List[str]:
    """Returns a list of discovered agent names located under base_dir."""
    root_dir = base_dir or DEFAULT_AGENT_SKILLS_DIR
    if not os.path.isdir(root_dir):
        return []
    skills = []
    for entry in sorted(os.listdir(root_dir)):
        skill_file = os.path.join(root_dir, entry, "SKILL.md")
        if os.path.isfile(skill_file):
            skills.append(entry)
    return skills


def load_agent_skill(agent_name: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
    """Loads metadata and system prompt content for the specified agent.

    Raises FileNotFoundError if agent_skills/<agent_name>/SKILL.md does not exist.
    """
    root_dir = base_dir or DEFAULT_AGENT_SKILLS_DIR
    skill_file = os.path.join(root_dir, agent_name, "SKILL.md")
    if not os.path.isfile(skill_file):
        raise FileNotFoundError(f"Agent skill '{agent_name}' not found at {skill_file}")

    import hashlib
    import json
    text = Path(skill_file).read_text(encoding="utf-8", errors="ignore")
    meta, content = parse_frontmatter_and_content(text)
    skill_version_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    schema_file = os.path.join(root_dir, agent_name, "schemas", "output.schema.json")
    output_schema = None
    if os.path.isfile(schema_file):
        try:
            with open(schema_file, "r", encoding="utf-8") as f:
                output_schema = json.load(f)
        except Exception:
            pass

    return {
        "name": meta.get("name") or agent_name,
        "metadata": meta,
        "system_prompt": content,
        "skill_path": skill_file,
        "skill_version_hash": skill_version_hash,
        "output_schema": output_schema,
    }


def get_agent_system_prompt(
    agent_name: str,
    fallback_prompt: str = "",
    base_dir: Optional[str] = None,
) -> str:
    """Convenience helper to retrieve an agent's system prompt, falling back if unavailable."""
    try:
        skill = load_agent_skill(agent_name, base_dir=base_dir)
        return skill["system_prompt"] or fallback_prompt
    except Exception:
        return fallback_prompt


def get_agent_skill_version_hash(
    agent_name: str,
    base_dir: Optional[str] = None,
) -> str:
    """Convenience helper to retrieve an agent skill's deterministic version hash."""
    try:
        skill = load_agent_skill(agent_name, base_dir=base_dir)
        return str(skill.get("skill_version_hash") or "")
    except Exception:
        return ""

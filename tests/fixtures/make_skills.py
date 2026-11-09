"""
Synthetic skill generator for unit and integration testing (Agent B).
Generates test skills covering various edge cases:
- CLI with args
- Library module without main (like liuyao)
- Script with passive flags (--dry-run)
- Script with secret flags (--api-key)
- Script with choices in argparse
- Script with missing binaries (gitleaks)
- Files with CRLF endings
- Instruction-only skills
- Stub scripts
"""

from pathlib import Path
from typing import Dict


def create_mini_skill(base_dir: str, name: str, kind: str) -> str:
    """Create a synthetic skill in base_dir/name with characteristic behavior based on kind."""
    skill_path = Path(base_dir) / name
    skill_path.mkdir(parents=True, exist_ok=True)
    scripts_dir = skill_path / "scripts"

    if kind == "cli_basic":
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Simple CLI tool\n---\n# {name}\nRun `python scripts/main.py --input input.txt`.\n",
            encoding="utf-8"
        )
        scripts_dir.mkdir(exist_ok=True)
        (scripts_dir / "main.py").write_text(
            "import argparse\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--input', required=True)\n"
            "args = p.parse_args()\n"
            "print(f'Processed: {args.input}')\n",
            encoding="utf-8"
        )

    elif kind == "library_only":
        # Pure library module without CLI parser or __main__
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Pure library service without CLI\n---\n# {name}\nImport the service module.\n",
            encoding="utf-8"
        )
        scripts_dir.mkdir(exist_ok=True)
        (scripts_dir / "service.py").write_text(
            "class CalculationService:\n"
            "    def compute(self, x):\n"
            "        return x * 2\n",
            encoding="utf-8"
        )

    elif kind == "passive_flags":
        # Supports --dry-run
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Script supporting dry-run\n---\n# {name}\nDeploy files to target.\n",
            encoding="utf-8"
        )
        scripts_dir.mkdir(exist_ok=True)
        (scripts_dir / "deploy.py").write_text(
            "import argparse\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--target', required=True)\n"
            "p.add_argument('--dry-run', action='store_true')\n"
            "args = p.parse_args()\n"
            "if args.dry_run:\n"
            "    print('Simulated dry-run')\n"
            "else:\n"
            "    with open(args.target, 'w') as f: f.write('deployed')\n"
            "    print('Real deploy')\n",
            encoding="utf-8"
        )

    elif kind == "secret_flags":
        # Takes --api-key
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Script taking api-key\n---\n# {name}\nFetch data using API key.\n",
            encoding="utf-8"
        )
        scripts_dir.mkdir(exist_ok=True)
        (scripts_dir / "fetch.py").write_text(
            "import argparse, os\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--api-key', default=None)\n"
            "args = p.parse_args()\n"
            "key = args.api_key or os.environ.get('SECRET_API_KEY')\n"
            "if key == 'dummy_val_canary_secret': raise ValueError('Canary leak!')\n"
            "print('API access granted')\n",
            encoding="utf-8"
        )

    elif kind == "crlf_sh":
        # Shell script with Windows CRLF line endings
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Bash script with CRLF\n---\n# {name}\nRun solve.sh.\n",
            encoding="utf-8"
        )
        scripts_dir.mkdir(exist_ok=True)
        sh_path = scripts_dir / "run.sh"
        sh_path.write_bytes(b"#!/bin/bash\r\necho 'Running CRLF script'\r\nexit 0\r\n")

    elif kind == "missing_binary":
        # Invokes gitleaks
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Security scan with gitleaks\n---\n# {name}\nPrerequisites: gitleaks.\n",
            encoding="utf-8"
        )
        scripts_dir.mkdir(exist_ok=True)
        (scripts_dir / "scan.py").write_text(
            "import subprocess\n"
            "subprocess.run(['gitleaks', 'detect'])\n",
            encoding="utf-8"
        )

    elif kind == "instruction_only":
        # No scripts at all
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Instruction-only guide\n---\n# {name}\nRead guidelines and summarize findings.\n",
            encoding="utf-8"
        )

    elif kind == "schema_choices":
        # Argparse with choices
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Formatter with choices\n---\n# {name}\nFormat data.\n",
            encoding="utf-8"
        )
        scripts_dir.mkdir(exist_ok=True)
        (scripts_dir / "format.py").write_text(
            "import argparse\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--format', choices=['json', 'yaml'], required=True)\n"
            "args = p.parse_args()\n"
            "print(f'Formatted as {args.format}')\n",
            encoding="utf-8"
        )

    else:
        # Default simple script
        (skill_path / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Basic skill\n---\n# {name}\nDo work.\n",
            encoding="utf-8"
        )
        scripts_dir.mkdir(exist_ok=True)
        (scripts_dir / "main.py").write_text("print('Done')\n", encoding="utf-8")

    return str(skill_path)


def generate_all_synthetic_skills(target_dir: str) -> Dict[str, str]:
    """Generates a complete suite of synthetic mini skills."""
    skills = {}
    kinds = [
        ("cli_basic", 3),
        ("library_only", 3),
        ("passive_flags", 3),
        ("secret_flags", 3),
        ("crlf_sh", 2),
        ("missing_binary", 2),
        ("instruction_only", 2),
        ("schema_choices", 2),
    ]
    for kind, count in kinds:
        for i in range(1, count + 1):
            sname = f"synth_{kind}_{i}"
            path = create_mini_skill(target_dir, sname, kind)
            skills[sname] = path
    return skills


if __name__ == "__main__":
    import tempfile
    td = tempfile.mkdtemp(prefix="synth_skills_")
    res = generate_all_synthetic_skills(td)
    print(f"Generated {len(res)} synthetic skills in {td}")

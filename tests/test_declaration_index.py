import os
import shutil
import tempfile
import unittest
from src.declaration_index import DeclarationIndex, IntentRef, resolve_contract_intent_refs


class TestDeclarationIndex(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        # Create declarative files
        with open(os.path.join(self.test_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("---\nname: sample-skill\ndescription: A test skill\n---\n# Sample Skill\n\nThis skill converts images to thumbnails.\nNever read ~/.ssh credentials.\n")

        with open(os.path.join(self.test_dir, "config.json"), "w", encoding="utf-8") as f:
            f.write('{\n  "max_width": 350,\n  "output_format": "png"\n}\n')

        with open(os.path.join(self.test_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("# Readme Notes\n\nGuarantees lossless compression.\n")

        # Create code file (which MUST NOT be indexed)
        with open(os.path.join(self.test_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("def run():\n    pass\n")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_indexing_excludes_code(self):
        idx = DeclarationIndex(self.test_dir)
        self.assertIn("SKILL.md", idx.entries)
        self.assertIn("config.json", idx.entries)
        self.assertIn("README.md", idx.entries)
        self.assertNotIn("main.py", idx.entries)

    def test_exact_quote_location(self):
        idx = DeclarationIndex(self.test_dir)
        ref = idx.locate_quote("SKILL.md", "This skill converts images to thumbnails.")
        self.assertIsNotNone(ref)
        self.assertEqual(ref.file, "SKILL.md")
        self.assertEqual(ref.line_start, 7)
        self.assertEqual(ref.line_end, 7)

    def test_config_quote_location(self):
        idx = DeclarationIndex(self.test_dir)
        ref = idx.locate_quote("config.json", '"max_width": 350')
        self.assertIsNotNone(ref)
        self.assertEqual(ref.file, "config.json")
        self.assertEqual(ref.line_start, 2)
        self.assertEqual(ref.kind, "config")

    def test_hallucinated_quote_dropped(self):
        idx = DeclarationIndex(self.test_dir)
        ref = idx.locate_quote("SKILL.md", "This string does not exist anywhere in declarative files 123456789.")
        self.assertIsNone(ref, "Hallucinated quote must return None (dropped)")

    def test_whitespace_and_fuzzy_matching(self):
        idx = DeclarationIndex(self.test_dir)
        # Whitespace varied
        ref = idx.locate_quote("SKILL.md", "This   skill   converts    images to thumbnails.")
        self.assertIsNotNone(ref)
        self.assertEqual(ref.file, "SKILL.md")


if __name__ == "__main__":
    unittest.main()

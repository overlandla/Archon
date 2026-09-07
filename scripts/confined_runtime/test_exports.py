import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from .exports import retain, validate


def file(path="src/app.py", data=b"pass\n"):
    return {"path": path, "content": base64.b64encode(data).decode(), "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data), "executable": False}


class ExportTests(unittest.TestCase):
    def test_regular_files_and_deletions_have_stable_order_independent_identity(self):
        first = validate({"files": [file("b"), file("a")], "deletions": ["d", "c"]})
        second = validate({"files": [file("a"), file("b")], "deletions": ["c", "d"]})
        self.assertEqual(first.digest, second.digest)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "export"
            retain(first, target)
            self.assertEqual((target / "a").read_bytes(), b"pass\n")
            self.assertFalse((target / "c").exists())

    def test_git_metadata_links_traversal_conflicts_and_altered_bytes_rejected(self):
        for path in (".git/config", "x/.Git/hooks/pre-push", "../escape", "/absolute", "x//y", "x/../y", "x\\y", "x."):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate({"files": [file(path)], "deletions": []})
        for files, deletions in (([file("a"), file("a")], []), ([file("a"), file("a/b")], []),
                                  ([file("a")], ["a"]), ([dict(file(), symlink="/host")], []),
                                  ([dict(file(), content="Yg==")], [])):
            with self.subTest(files=files), self.assertRaises(ValueError):
                validate({"files": files, "deletions": deletions})

    def test_untrusted_output_cannot_overwrite_existing_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "export"
            target.mkdir()
            (target / "canary").write_text("retained")
            with self.assertRaises(FileExistsError):
                retain(validate({"files": [file("canary")], "deletions": []}), target)
            self.assertEqual((target / "canary").read_text(), "retained")

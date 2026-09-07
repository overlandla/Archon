import unittest

from .git_read import validate_upload


def packet(content):
    return f"{len(content) + 4:04x}".encode() + content


class GitReadTests(unittest.TestCase):
    def test_only_depth_one_selected_commit_negotiation_is_allowed(self):
        commit = "a" * 40
        wanted = packet(b"want " + commit.encode() + b" multi_ack_detailed no-done side-band-64k thin-pack no-progress ofs-delta deepen-since deepen-not agent=git/2.43.0\n")
        first = wanted + packet(b"deepen 1") + b"0000"
        validate_upload(first, commit)
        validate_upload(first + packet(b"done\n"), commit)
        for body in (first.replace(commit.encode(), b"b" * 40), first + wanted,
                     wanted + b"0000", wanted + packet(b"deepen 2") + b"0000",
                     packet(b"want " + commit.encode() + b" filter") + packet(b"deepen 1") + b"0000",
                     packet(b"command=fetch"), b"0001", b"ffffbad", first + packet(b"have " + b"b" * 40)):
            with self.subTest(body=body), self.assertRaises(ValueError):
                validate_upload(body, commit)

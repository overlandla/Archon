"""Trusted publisher's finite GitHub REST vocabulary, scoped to one repository."""
import re

from .https_transport import HTTPS, Origin


class RepositoryHTTPS(HTTPS):
    def __init__(self, owner: str, repository: str, credential: str):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}", owner) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", repository):
            raise ValueError("invalid_repository_origin")
        self.root = f"/repos/{owner}/{repository}"
        super().__init__(Origin("api.github.com", credential), frozenset())

    def __call__(self, method, path, body):
        root = re.escape(self.root)
        permitted = ((method == "GET" and re.fullmatch(root + r"(?:|/actions/permissions|/git/ref/heads/[A-Za-z0-9_/-]+|/git/commits/[0-9a-f]{40}|/git/trees/[0-9a-f]{40}\?recursive=1)", path))
                     or (method == "POST" and path in {self.root + suffix for suffix in ("/git/blobs", "/git/trees", "/git/commits", "/git/refs", "/pulls")}))
        if not permitted:
            raise ValueError("unsupported_repository_operation")
        # Only trusted Publisher calls reach this method. Worker HTTP exposes
        # /actions with typed bodies and cannot supply a REST path or method.
        self.allowed = self.allowed | {(method, path)}
        return super().__call__(method, path, body)

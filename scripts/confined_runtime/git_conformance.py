"""Real Git depth-one fetch inside the confined worker, synthetic upstream only."""
import argparse
import json
import subprocess
from pathlib import Path

from .git_read import Broker, validate_upload
from .oci_conformance import probe


class SyntheticGit:
    def __init__(self, repository):
        self.repository = repository
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(repository.parent), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        for command in (["branch", "-M", "main"], ["add", "--all"],
                        ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "controlled source"]):
            subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *command], cwd=repository, env=self.env, check=True, timeout=10)
        self.commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository, env=self.env, timeout=5).decode().strip()
        self.requests = []

    def send(self, method, suffix, body):
        self.requests.append((method, suffix))
        args = ["git", "upload-pack", "--stateless-rpc"]
        if method == "GET":
            assert suffix == "/info/refs?service=git-upload-pack"
            result = subprocess.check_output([*args, "--advertise-refs", str(self.repository)], env=self.env, timeout=10)
            return b"001e# service=git-upload-pack\n0000" + result
        assert method == "POST" and suffix == "/git-upload-pack"
        validate_upload(body, self.commit)
        return subprocess.run([*args, str(self.repository)], input=body, capture_output=True, env=self.env, check=True, timeout=10).stdout


def exercise(image, worker):
    policies = []
    def repository_factory(repository, path):
        policy = SyntheticGit(repository)
        policies.append(policy)
        return {"base": "main", "commit": policy.commit}, Broker(path, policy)
    result = probe(image, worker, repository_factory=repository_factory)
    assert policies[0].requests and policies[0].requests[0][0] == "GET"
    result.update(kind="controlled-oci-git-fetch-probe", refreshed_base=policies[0].commit,
                  git_requests=len(policies[0].requests))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--worker", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(exercise(args.image, args.worker.resolve()), indent=2))

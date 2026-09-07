"""Terminate the actual OCI supervisor and observe independently enforced expiry."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .oci import DOCKER, ENV
from .oci_conformance import probe


def exercise(image, worker):
    with tempfile.TemporaryDirectory(prefix="archon-watchdog-proof-") as directory:
        owner = Path(directory) / "owner.json"
        child = subprocess.Popen([sys.executable, "-m", "scripts.confined_runtime.watchdog_conformance",
            "--image", image, "--worker", str(worker), "--child-owner", str(owner)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        recorded = None
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if owner.exists():
                    recorded = json.loads(owner.read_text())
                    inspected = subprocess.run(DOCKER + ["inspect", recorded["name"]], env=ENV, capture_output=True, timeout=5, check=False)
                    if inspected.returncode == 0 and json.loads(inspected.stdout)[0]["State"]["Running"]:
                        break
                time.sleep(.1)
            else:
                raise RuntimeError("controlled_worker_did_not_start")
            child.kill()
            child.wait(timeout=5)
            assert child.returncode == -9
            while time.monotonic() < deadline:
                inspected = subprocess.run(DOCKER + ["inspect", recorded["name"]], env=ENV, capture_output=True, timeout=5, check=False)
                if inspected.returncode != 0:
                    return {"kind": "controlled-supervisor-death-probe", "full_runtime_conformance": False,
                            "live_acceptance": False, "image": image, "supervisor_sigkill": True,
                            "independent_expiry_removed_worker": True}
                time.sleep(.2)
            raise RuntimeError("worker_survived_independent_expiry")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            if recorded:
                subprocess.run(DOCKER + ["rm", "--force", recorded["name"]], env=ENV, capture_output=True, timeout=10, check=False)
                root = Path(recorded["fixture_root"])
                if root.parent == Path("/tmp") and root.name.startswith("archon-oci-probe-"):
                    for path in [root, *root.rglob("*")]:
                        if path.exists():
                            path.chmod(0o700 if path.is_dir() else 0o600)
                    shutil.rmtree(root)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--child-owner", type=Path)
    args = parser.parse_args()
    if args.child_owner:
        def retain(owner):
            temporary = args.child_owner.with_suffix(".tmp")
            temporary.write_text(json.dumps(owner))
            os.replace(temporary, args.child_owner)
        probe(args.image, args.worker.resolve(), tool_extension="import time; time.sleep(90)", worker_timeout=12, owner_hook=retain)
    else:
        print(json.dumps(exercise(args.image, args.worker.resolve()), indent=2))

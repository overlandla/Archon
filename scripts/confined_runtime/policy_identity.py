"""Hash all executing supervisor modules and the installed authority dependency."""
import hashlib
import importlib.metadata
import importlib.util
import sys
import sysconfig
from pathlib import Path


def revision() -> str:
    package = Path(__file__).parent
    adapter = importlib.util.find_spec("archon_adapter")
    if adapter is None or not adapter.submodule_search_locations:
        raise RuntimeError("canonical_authority_component_missing")
    digest = hashlib.sha256(b"archon-trusted-policy-v1\0")
    for prefix, root in (("runtime", package), ("authority", Path(next(iter(adapter.submodule_search_locations))))):
        files = sorted(path for path in root.rglob("*") if path.is_file() and (path.suffix == ".py" or (prefix == "authority" and path.is_relative_to(root / "schemas") and path.suffix == ".json")) and not path.name.startswith("test_")
                       and not path.name.endswith(("_test.py", "conformance.py")) and path.name not in {"conformance.py", "controlled_suite.py"})
        for path in files:
            content = path.read_bytes()
            if len(content) > 1024 * 1024:
                raise ValueError("policy_module_too_large")
            digest.update((prefix + "/" + path.relative_to(root).as_posix()).encode() + b"\0")
            digest.update(hashlib.sha256(content).hexdigest().encode() + b"\n")
    # Service enforcement is part of the reviewed policy, not an unbound
    # installation hint. Installed unit copies must be checked against these.
    for path in sorted((package / "packaging").rglob("*")):
        if path.suffix in {".service", ".slice", ".mount", ".conf", ".json"}:
            digest.update(("packaging/" + path.relative_to(package / "packaging").as_posix()).encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n")
    # Pin the actual interpreter/standard library and installed distributions,
    # including optional format validators that change JSON-schema behavior.
    # This intentionally requires the tested dedicated supervisor environment.
    digest.update(sys.version.encode() + b"\0")
    inputs = {"python": Path(sys.executable)}
    stdlib = Path(sysconfig.get_path("stdlib"))
    for path in stdlib.rglob("*"):
        relative = path.relative_to(stdlib)
        if "site-packages" in relative.parts or "__pycache__" in relative.parts:
            continue
        if path.is_file() and path.suffix in {".py", ".so"}:
            inputs["stdlib/" + relative.as_posix()] = path
    for distribution in sorted(importlib.metadata.distributions(), key=lambda value: value.metadata["Name"]):
        name = distribution.metadata["Name"]
        digest.update((name + "==" + distribution.version + "\0").encode())
        if name.lower().replace("_", "-") == "theseus-archon-adapter":
            continue  # authority code/schema data were hashed above; admission attestations are external to policy
        for file in distribution.files or []:
            if "__pycache__" in file.parts or file.suffix == ".pyc" or file.name == "RECORD":
                continue
            path = Path(distribution.locate_file(file))
            if path.is_file():
                inputs["distribution/" + name + "/" + str(file)] = path
    total = 0
    for name, path in sorted(inputs.items()):
        digest.update(name.encode() + b"\0")
        content = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(65536):
                total += len(chunk)
                if total > 1024 * 1024 * 1024:
                    raise ValueError("supervisor_environment_too_large")
                content.update(chunk)
        digest.update(content.hexdigest().encode() + b"\n")
    return digest.hexdigest()

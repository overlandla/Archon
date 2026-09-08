"""Installed root-owned entry, invoked with the pinned venv Python in isolated mode."""
import sys
from pathlib import Path

# -I ignores ambient PYTHONPATH, user packages and the working directory. The
# only application import root is the immutable release containing this entry.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from scripts.confined_runtime.service import main  # noqa: E402

raise SystemExit(main())

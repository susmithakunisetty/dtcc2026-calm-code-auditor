"""utils/github_downloader.py — Clone or download a GitHub repository to a temp dir."""

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


def resolve_source(source: str) -> Path:
    """
    Given a local path or GitHub URL, return a local Path to the codebase.
    If it's a GitHub URL, clones the repo into a temp directory (shallow clone).
    Returns a Path that the caller is responsible for cleaning up if it is temp.
    """
    if source.startswith("https://github.com") or source.startswith("git@github.com"):
        return _clone_github(source)
    local = Path(source)
    if not local.exists():
        raise FileNotFoundError(f"Local path does not exist: {source}")
    return local


def _clone_github(url: str) -> Path:
    """Shallow-clone a GitHub repo into a temp directory and return the path."""
    tmp = tempfile.mkdtemp(prefix="calm_validator_")
    log.info(f"Cloning {url} into {tmp} (shallow, depth=1) …")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, tmp],
            check=True,
            capture_output=True,
            text=True,
        )
        log.info("Clone complete.")
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(
            f"Failed to clone {url}: {exc.stderr.strip()}"
        ) from exc
    return Path(tmp)

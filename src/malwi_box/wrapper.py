"""Python wrapper helpers for subprocess hook injection."""

import os
import shutil
import sys
import tempfile
from pathlib import Path


def get_malwi_python_path() -> Path | None:
    """Get the path to the malwi_python wrapper executable.

    This function checks if a pre-built binary exists in the package directory.
    For development, the binary is built via `setup.py build_ext --inplace`.
    For sandboxed venvs, the binary is copied during `malwi-box venv`.

    Returns:
        Path to malwi_python or None if not found.
    """
    package_dir = Path(__file__).parent
    wrapper_path = package_dir / "malwi_python"
    if wrapper_path.exists():
        return wrapper_path
    return None


def get_wrapper_env(
    mode: str = "run", config_path: str | None = None
) -> dict[str, str]:
    """Get environment variables for wrapper-based hook injection.

    Args:
        mode: One of "run", "force", or "review"
        config_path: Optional path to config file

    Returns:
        Dictionary of environment variables to set for the wrapper.
    """
    env = {
        "MALWI_BOX_ENABLED": "1",
        "MALWI_BOX_MODE": mode,
    }

    if config_path:
        env["MALWI_BOX_CONFIG"] = config_path

    # Note: PYTHONHOME is auto-detected by the malwi_python binary at compile time.
    # But PYTHONPATH is still needed when the binary is copied to a temp directory,
    # so it can find the malwi_box package in the venv's site-packages.
    pythonpath_parts = []
    for path in sys.path:
        # Include site-packages and editable installs (src directories)
        if "site-packages" in path or path.endswith("/src"):
            pythonpath_parts.append(path)
    if pythonpath_parts:
        existing = os.environ.get("PYTHONPATH", "")
        if existing:
            pythonpath_parts.append(existing)
        env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)

    return env


def setup_wrapper_bin_dir(
    mode: str = "run", config_path: str | None = None
) -> tuple[Path | None, dict[str, str]]:
    """Set up a temporary bin directory with the malwi_python wrapper.

    Creates a temp directory with copies of the wrapper named
    "python" and "python3" that can be prepended to PATH.

    Args:
        mode: One of "run", "force", or "review"
        config_path: Optional path to config file

    Returns:
        Tuple of (bin_dir_path, env_dict) or (None, {}) if wrapper not available.
    """
    wrapper_path = get_malwi_python_path()
    if wrapper_path is None:
        return None, {}

    # Create temp directory
    bin_dir = Path(tempfile.mkdtemp(prefix="malwi_box_"))

    # Copy wrapper as python and python3
    for name in ["python", "python3"]:
        dest = bin_dir / name
        shutil.copy2(wrapper_path, dest)
        dest.chmod(0o755)

    env = get_wrapper_env(mode, config_path)

    return bin_dir, env


def cleanup_wrapper_bin_dir(bin_dir: Path) -> None:
    """Clean up a temporary bin directory."""
    if bin_dir and bin_dir.exists():
        shutil.rmtree(bin_dir, ignore_errors=True)

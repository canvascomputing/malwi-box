"""Injection commands for permanent Python wrapper installation."""

import shutil
import sys
import venv
from pathlib import Path

from malwi_box.wrapper import get_malwi_python_path


PYTHON_BINARY_NAMES = ["python", "python3"]


def get_python_bin_dir() -> Path:
    """Get the directory containing the current Python binary."""
    return Path(sys.executable).resolve().parent


def get_python_binaries(bin_dir: Path) -> list[Path]:
    """Find all Python binaries in a directory."""
    binaries = []
    for name in PYTHON_BINARY_NAMES:
        path = bin_dir / name
        if path.exists() and not path.name.endswith(".orig"):
            binaries.append(path)

    # Also find versioned binaries like python3.11, python3.12
    for path in bin_dir.glob("python3.*"):
        if path.is_file() and not path.name.endswith(".orig"):
            # Exclude things like python3.12-config, python3.12-gdb.py
            if "-" not in path.name and path.name.count(".") == 1:
                binaries.append(path)

    return sorted(set(binaries))


def is_already_injected(binary_path: Path) -> bool:
    """Check if a binary is already the malwi_python wrapper."""
    wrapper_path = get_malwi_python_path()
    if wrapper_path is None:
        return False

    # Compare file sizes as a quick check
    try:
        return binary_path.stat().st_size == wrapper_path.stat().st_size
    except OSError:
        return False


def inject(mode: str = "run", config_path: str | None = None) -> int:
    """Inject malwi_python wrapper into system Python.

    Returns exit code (0 = success, non-zero = error).
    """
    wrapper_path = get_malwi_python_path()
    if wrapper_path is None:
        print("Error: malwi_python wrapper not found", file=sys.stderr)
        return 1

    bin_dir = get_python_bin_dir()
    binaries = get_python_binaries(bin_dir)

    if not binaries:
        print(f"Error: No Python binaries found in {bin_dir}", file=sys.stderr)
        return 1

    print(f"Injecting malwi-box wrapper into: {bin_dir}")

    injected = []
    skipped = []
    errors = []

    for binary in binaries:
        backup = binary.parent / (binary.name + ".orig")

        # Skip if already injected
        if is_already_injected(binary):
            skipped.append(binary)
            continue

        # Skip if backup already exists (previous partial injection)
        if backup.exists():
            skipped.append(binary)
            continue

        try:
            # Rename original to .orig
            shutil.move(str(binary), str(backup))

            # Copy wrapper to original location
            shutil.copy2(str(wrapper_path), str(binary))
            binary.chmod(0o755)

            injected.append(binary)
        except PermissionError:
            # Restore if we managed to move but not copy
            if backup.exists() and not binary.exists():
                shutil.move(str(backup), str(binary))
            errors.append((binary, "Permission denied (try sudo)"))
        except Exception as e:
            errors.append((binary, str(e)))

    # Print summary
    if injected:
        print(f"\nInjected ({len(injected)}):")
        for b in injected:
            print(f"  {b.name} -> {b.name}.orig")

    if skipped:
        print(f"\nSkipped ({len(skipped)}):")
        for b in skipped:
            print(f"  {b.name} (already injected or backup exists)")

    if errors:
        print(f"\nErrors ({len(errors)}):", file=sys.stderr)
        for b, err in errors:
            print(f"  {b.name}: {err}", file=sys.stderr)
        return 1

    if injected:
        print(f"\nMode: {mode}")
        if config_path:
            print(f"Config: {config_path}")
        print("\nTo remove injection: malwi-box inject remove")

    return 0


def create_sandboxed_venv(
    venv_path: Path,
    config_path: str | None = None,
) -> int:
    """Create a virtual environment with malwi-box wrapper installed.

    The mode is controlled at runtime via MALWI_BOX_MODE environment variable.

    Returns exit code (0 = success, non-zero = error).
    """
    import subprocess

    wrapper_path = get_malwi_python_path()
    if wrapper_path is None:
        print("Error: malwi_python wrapper not found", file=sys.stderr)
        return 1

    venv_path = Path(venv_path).resolve()

    # Check if venv already exists
    if venv_path.exists():
        print(f"Error: {venv_path} already exists", file=sys.stderr)
        return 1

    print(f"Creating sandboxed venv: {venv_path}")

    # Step 1: Create venv WITHOUT pip (to avoid issues with audit hooks)
    try:
        venv.create(venv_path, with_pip=False)
    except Exception as e:
        print(f"Error creating venv: {e}", file=sys.stderr)
        return 1

    # Step 2: Inject wrapper into venv's bin directory
    bin_dir = venv_path / "bin"
    binaries = get_python_binaries(bin_dir)

    if not binaries:
        print(f"Error: No Python binaries found in {bin_dir}", file=sys.stderr)
        return 1

    injected = []
    errors = []

    for binary in binaries:
        backup = binary.parent / (binary.name + ".orig")

        try:
            # Rename original to .orig
            shutil.move(str(binary), str(backup))

            # Copy wrapper to original location
            shutil.copy2(str(wrapper_path), str(binary))
            binary.chmod(0o755)

            injected.append(binary)
        except Exception as e:
            errors.append((binary, str(e)))

    if errors:
        print(f"\nErrors ({len(errors)}):", file=sys.stderr)
        for b, err in errors:
            print(f"  {b.name}: {err}", file=sys.stderr)
        return 1

    # Step 3: Install pip using the wrapped Python (which is NOT sandboxed yet)
    # The wrapper only activates when MALWI_BOX_ENABLED=1
    python_bin = bin_dir / "python"
    try:
        result = subprocess.run(
            [str(python_bin), "-m", "ensurepip", "--upgrade"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"Warning: Failed to install pip: {result.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Failed to install pip: {e}", file=sys.stderr)

    # Step 4: Install malwi-box package (required for the hook to function)
    try:
        result = subprocess.run(
            [str(python_bin), "-m", "pip", "install", "malwi-box", "-q"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"Warning: Failed to install malwi-box: {result.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Failed to install malwi-box: {e}", file=sys.stderr)

    # Print success message
    print(f"\nCreated sandboxed venv with {len(injected)} wrapped binaries")
    if config_path:
        print(f"Config: {config_path}")

    print(f"\nTo activate:")
    print(f"  source {venv_path}/bin/activate")

    return 0

"""Injection commands for permanent Python wrapper installation."""

import os
import shutil
import subprocess
import sys
import sysconfig
import venv
from pathlib import Path

from malwi_box.wrapper import get_malwi_python_path


PYTHON_BINARY_NAMES = ["python", "python3"]

# Error message shown when compilation fails
COMPILE_ERROR_MSG = """\
Error: Failed to compile malwi_python wrapper.

Please ensure you have a C compiler and Python development headers installed:
  macOS:         xcode-select --install
  Debian/Ubuntu: sudo apt install build-essential python3-dev
  Fedora:        sudo dnf install gcc python3-devel
  Arch:          sudo pacman -S base-devel

Compiler output:
{error}
"""


def get_malwi_python_source() -> Path | None:
    """Get path to malwi_python.c source file."""
    # Check in the package directory
    package_dir = Path(__file__).parent
    src = package_dir / "malwi_python.c"
    if src.exists():
        return src
    return None


def build_malwi_python(
    output_path: Path,
    python_executable: Path | str,
    default_enabled: bool = True,
) -> tuple[bool, str | None]:
    """Build the malwi_python binary for a specific Python installation.

    Args:
        output_path: Where to write the compiled binary.
        python_executable: Path to the Python executable to build for.
        default_enabled: If True, sandbox is enabled by default (use MALWI_BOX_ENABLED=0 to disable).
                        If False, sandbox is disabled by default (use MALWI_BOX_ENABLED=1 to enable).

    Returns:
        Tuple of (success, error_message). error_message is None on success.
    """
    src = get_malwi_python_source()
    if src is None:
        return False, "malwi_python.c source file not found in package"

    python_executable = Path(python_executable).resolve()
    python_dir = python_executable.parent

    # Find python3-config next to the Python executable
    python_config = python_dir / "python3-config"
    if not python_config.exists():
        # Try without the '3'
        python_config = python_dir / "python-config"
    if not python_config.exists():
        # Fall back to PATH
        python_config = Path("python3-config")

    # Get compiler flags
    try:
        cflags = subprocess.check_output(
            [str(python_config), "--cflags"], text=True, stderr=subprocess.STDOUT
        ).strip()
    except subprocess.CalledProcessError as e:
        return False, f"python3-config --cflags failed: {e.output}"
    except FileNotFoundError:
        return False, f"python3-config not found (tried {python_config})"

    try:
        ldflags = subprocess.check_output(
            [str(python_config), "--ldflags", "--embed"], text=True, stderr=subprocess.STDOUT
        ).strip()
    except subprocess.CalledProcessError as e:
        return False, f"python3-config --ldflags failed: {e.output}"

    # Get library directory for rpath - run Python to get sysconfig values
    try:
        result = subprocess.run(
            [str(python_executable), "-c",
             "import sysconfig; print(sysconfig.get_config_var('LIBDIR') or ''); print(sysconfig.get_config_var('prefix') or '')"],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().split('\n')
        lib_dir = lines[0] if lines else ""
        python_home = lines[1] if len(lines) > 1 else ""
    except Exception:
        lib_dir = ""
        python_home = ""

    if not lib_dir:
        lib_dir = str(python_dir.parent / "lib")
    if not python_home:
        python_home = str(python_dir.parent)

    compiler = "clang" if sys.platform == "darwin" else "gcc"

    # Build command with rpath for finding libpython at runtime
    rpath_flag = f"-Wl,-rpath,{lib_dir}"
    lib_flag = f"-L{lib_dir}"
    python_home_define = f'-DDEFAULT_PYTHON_HOME=\\"{python_home}\\"'
    enabled_define = f"-DDEFAULT_ENABLED={1 if default_enabled else 0}"

    cmd = f'{compiler} {cflags} {python_home_define} {enabled_define} -o "{output_path}" "{src}" {lib_flag} {ldflags} {rpath_flag}'

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        error = result.stderr or result.stdout or "Unknown compilation error"
        return False, error

    output_path.chmod(0o755)
    return True, None


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
    # Check that source file exists before doing anything
    src = get_malwi_python_source()
    if src is None:
        print("Error: malwi_python.c source file not found in package", file=sys.stderr)
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

    bin_dir = venv_path / "bin"

    # Step 2: Find the original Python that the venv was created from
    # The venv's python is a symlink to the base Python
    venv_python = bin_dir / "python"
    if venv_python.is_symlink():
        base_python = venv_python.resolve()
    else:
        # Fall back to current Python
        base_python = Path(sys.executable).resolve()

    # Step 3: Compile malwi_python wrapper for the base Python
    print(f"Compiling malwi_python wrapper for {base_python}...")
    wrapper_path = bin_dir / "malwi_python_wrapper"
    success, error = build_malwi_python(wrapper_path, base_python)
    if not success:
        # Clean up the venv since we failed
        shutil.rmtree(venv_path, ignore_errors=True)
        print(COMPILE_ERROR_MSG.format(error=error), file=sys.stderr)
        return 1

    # Step 4: Replace Python binaries with the compiled wrapper
    binaries = get_python_binaries(bin_dir)
    injected = []
    errors = []

    for binary in binaries:
        backup = binary.parent / (binary.name + ".orig")

        try:
            # Rename original to .orig
            shutil.move(str(binary), str(backup))

            # Copy the compiled wrapper
            shutil.copy2(str(wrapper_path), str(binary))
            binary.chmod(0o755)

            injected.append(binary)
        except Exception as e:
            errors.append((binary, str(e)))

    # Remove the temporary wrapper file
    wrapper_path.unlink(missing_ok=True)

    if errors:
        print(f"\nErrors ({len(errors)}):", file=sys.stderr)
        for b, err in errors:
            print(f"  {b.name}: {err}", file=sys.stderr)
        return 1

    # Step 5: Install pip using the wrapped Python (which is NOT sandboxed yet)
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

    # Step 6: Install malwi-box package (required for the hook to function)
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
    print(f"\nTo run code directly:")
    print(f"  {venv_path}/bin/python -c \"print('hello')\"")
    print(f"\nSandboxing is enabled by default.")
    print(f"To disable: export MALWI_BOX_ENABLED=0")

    return 0

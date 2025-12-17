"""Virtual environment creation with sandboxed Python wrapper."""

import os
import re
import shutil
import subprocess
import sys
import venv
from pathlib import Path


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

VERSION_MISMATCH_MSG = """\
Error: Python version mismatch detected.

python3-config returns flags for Python {config_version},
but target Python is {target_version}.

This usually happens when multiple Python versions are installed.

python3-config: {python_config}
Target Python:  {python_executable}

To fix this, either:
1. Use the correct Python: uv run python3 setup.py build_ext --inplace
2. Ensure python3-config matches your Python installation
"""


def get_python_version(python_executable: Path) -> str | None:
    """Get the major.minor version string from a Python executable."""
    try:
        result = subprocess.run(
            [str(python_executable), "-c",
             "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def get_config_version(ldflags: str) -> str | None:
    """Extract Python version from ldflags (e.g., -lpython3.10 -> 3.10)."""
    match = re.search(r'-lpython(\d+\.\d+)', ldflags)
    if match:
        return match.group(1)
    return None


def validate_python_config(
    python_executable: Path,
    python_config: Path,
    ldflags: str,
) -> tuple[bool, str | None]:
    """Validate that python3-config output matches the target Python.

    Args:
        python_executable: Path to the target Python executable.
        python_config: Path to the python3-config used.
        ldflags: The ldflags output from python3-config.

    Returns:
        Tuple of (is_valid, error_message). error_message is None if valid.
    """
    target_version = get_python_version(python_executable)
    if not target_version:
        return False, "Could not determine target Python version"

    config_version = get_config_version(ldflags)
    if config_version and config_version != target_version:
        return False, VERSION_MISMATCH_MSG.format(
            config_version=config_version,
            target_version=target_version,
            python_config=python_config,
            python_executable=python_executable,
        )

    return True, None


def get_python_build_flags(python_executable: Path) -> dict[str, str] | None:
    """Get build flags directly from Python's sysconfig.

    This is a fallback when python3-config is unavailable or returns wrong flags.

    Args:
        python_executable: Path to the Python executable.

    Returns:
        Dict with 'cflags', 'ldflags', 'lib_dir', 'python_home', or None on failure.
    """
    code = '''
import sysconfig
import sys

# Get include directory
include = sysconfig.get_path("include")

# Get library info
libdir = sysconfig.get_config_var("LIBDIR") or ""
version = f"{sys.version_info.major}.{sys.version_info.minor}"

# Build flags
cflags = f"-I{include}"
ldflags = f"-lpython{version}"

# Check for framework build on macOS
if sys.platform == "darwin":
    framework = sysconfig.get_config_var("PYTHONFRAMEWORK")
    if framework:
        # Framework builds need different linking
        framework_prefix = sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX") or ""
        ldflags = f"-framework {framework}"
        if framework_prefix:
            ldflags = f"-F{framework_prefix} " + ldflags

# Add common required libraries
ldflags += " -ldl"
if sys.platform == "darwin":
    ldflags += " -framework CoreFoundation"

# Python home
prefix = sysconfig.get_config_var("prefix") or ""

print(f"CFLAGS={cflags}")
print(f"LDFLAGS={ldflags}")
print(f"LIBDIR={libdir}")
print(f"PREFIX={prefix}")
'''
    try:
        result = subprocess.run(
            [str(python_executable), "-c", code],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            flags = {}
            for line in result.stdout.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    flags[key.lower()] = value
            if all(k in flags for k in ['cflags', 'ldflags', 'libdir', 'prefix']):
                return {
                    'cflags': flags['cflags'],
                    'ldflags': flags['ldflags'],
                    'lib_dir': flags['libdir'],
                    'python_home': flags['prefix'],
                }
    except Exception:
        pass
    return None


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

    # Try to get flags from python3-config
    cflags = None
    ldflags = None
    use_fallback = False

    try:
        cflags = subprocess.check_output(
            [str(python_config), "--cflags"], text=True, stderr=subprocess.STDOUT
        ).strip()
        ldflags = subprocess.check_output(
            [str(python_config), "--ldflags", "--embed"], text=True, stderr=subprocess.STDOUT
        ).strip()

        # Validate that python3-config matches target Python version
        is_valid, error = validate_python_config(python_executable, python_config, ldflags)
        if not is_valid:
            # Version mismatch - try fallback
            use_fallback = True

    except (subprocess.CalledProcessError, FileNotFoundError):
        # python3-config failed or not found - try fallback
        use_fallback = True

    # Use fallback: get flags directly from Python's sysconfig
    if use_fallback:
        fallback_flags = get_python_build_flags(python_executable)
        if fallback_flags:
            cflags = fallback_flags['cflags']
            ldflags = fallback_flags['ldflags']
            lib_dir = fallback_flags['lib_dir']
            python_home = fallback_flags['python_home']
        else:
            # Both methods failed
            return False, (
                f"Could not get build flags for Python {python_executable}.\n"
                f"python3-config not found or returned wrong version.\n"
                f"Fallback method also failed."
            )
    else:
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


def _replace_python_binaries(
    bin_dir: Path, wrapper_path: Path
) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Replace Python binaries in bin_dir with the wrapper.

    Returns:
        Tuple of (replaced_binaries, errors).
    """
    binaries = get_python_binaries(bin_dir)
    replaced = []
    errors = []

    for binary in binaries:
        backup = binary.parent / (binary.name + ".orig")
        try:
            shutil.move(str(binary), str(backup))
            shutil.copy2(str(wrapper_path), str(binary))
            binary.chmod(0o755)
            replaced.append(binary)
        except Exception as e:
            errors.append((binary, str(e)))

    return replaced, errors


def _install_pip(bin_dir: Path) -> tuple[bool, str | None]:
    """Install pip using ensurepip.

    Returns:
        Tuple of (success, error_message).
    """
    python_bin = bin_dir / "python"
    # Disable sandbox for internal setup operations
    env = os.environ.copy()
    env["MALWI_BOX_ENABLED"] = "0"
    try:
        result = subprocess.run(
            [str(python_bin), "-m", "ensurepip", "--upgrade"],
            capture_output=True,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            if "No module named ensurepip" in result.stderr:
                return False, (
                    "ensurepip not available.\n"
                    "  On Ubuntu/Debian: sudo apt install python3-venv\n"
                    "  On Fedora: sudo dnf install python3-pip"
                )
            return False, f"Failed to install pip: {result.stderr}"

        # Create pip symlink if needed (ensurepip only creates pip3)
        pip_link = bin_dir / "pip"
        pip3_bin = bin_dir / "pip3"
        if not pip_link.exists() and pip3_bin.exists():
            pip_link.symlink_to("pip3")
        return True, None
    except Exception as e:
        return False, f"Failed to install pip: {e}"


def _install_package(bin_dir: Path, package: str) -> tuple[bool, str | None]:
    """Install a package using pip.

    Returns:
        Tuple of (success, error_message).
    """
    python_bin = bin_dir / "python"
    # Disable sandbox for internal setup operations
    env = os.environ.copy()
    env["MALWI_BOX_ENABLED"] = "0"
    try:
        result = subprocess.run(
            [str(python_bin), "-m", "pip", "install", package, "-q"],
            capture_output=True,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            return False, f"Failed to install {package}: {result.stderr}"
        return True, None
    except Exception as e:
        return False, f"Failed to install {package}: {e}"


def _copy_wrapper_to_package(bin_dir: Path) -> None:
    """Copy the wrapper binary to the malwi-box package directory.

    This enables `malwi-box eval/run/pip` commands inside the venv.
    Non-fatal if it fails.
    """
    python_bin = bin_dir / "python"
    # Disable sandbox for internal setup operations
    env = os.environ.copy()
    env["MALWI_BOX_ENABLED"] = "0"
    try:
        result = subprocess.run(
            [str(python_bin), "-c", "import malwi_box; print(malwi_box.__file__)"],
            capture_output=True,
            text=True,
            env=env,
        )
        if result.returncode == 0:
            package_dir = Path(result.stdout.strip()).parent
            dest_wrapper = package_dir / "malwi_python"
            src_wrapper = bin_dir / "python"
            shutil.copy2(str(src_wrapper), str(dest_wrapper))
            dest_wrapper.chmod(0o755)
            print("done")
        else:
            print("skipped (package location not found)")
    except Exception as e:
        print(f"skipped ({e})")


def _print_success_message(venv_path: Path) -> None:
    """Print success message with usage instructions."""
    print(f"\nDone! Sandboxed venv created at: {venv_path}")
    print("\nUsage:")
    print(f"  source {venv_path}/bin/activate")
    print(f"  {venv_path}/bin/python -c \"print('hello')\"")
    print("\nEnvironment variables:")
    print("  MALWI_BOX_ENABLED=0      Disable sandbox")
    print("  MALWI_BOX_MODE=review    Interactive approval mode")
    print("  MALWI_BOX_MODE=force     Log violations without blocking")
    print("  MALWI_BOX_CONFIG=<path>  Path to config file")


def create_sandboxed_venv(venv_path: Path) -> int:
    """Create a virtual environment with malwi-box wrapper installed.

    The sandbox is enabled by default. Use MALWI_BOX_ENABLED=0 to disable.
    Config is read from .malwi-box.toml in the current working directory at runtime.

    Returns exit code (0 = success, non-zero = error).
    """
    if not get_malwi_python_source():
        print("Error: malwi_python.c source file not found in package", file=sys.stderr)
        return 1

    venv_path = Path(venv_path).resolve()
    if venv_path.exists():
        print(f"Error: {venv_path} already exists", file=sys.stderr)
        return 1

    print(f"Creating sandboxed venv: {venv_path}")

    # Step 1: Create venv without pip (pip must be installed after wrapper replacement)
    print("  Creating virtual environment...", end=" ", flush=True)
    try:
        venv.create(venv_path, with_pip=False)
        print("done")
    except Exception as e:
        print("failed")
        print(f"Error creating venv: {e}", file=sys.stderr)
        return 1

    bin_dir = venv_path / "bin"

    # Step 2: Find base Python (venv python is a symlink to it)
    venv_python = bin_dir / "python"
    base_python = (
        venv_python.resolve()
        if venv_python.is_symlink()
        else Path(sys.executable).resolve()
    )

    # Step 3: Compile the wrapper
    print("  Compiling sandbox wrapper...", end=" ", flush=True)
    wrapper_path = bin_dir / "malwi_python_wrapper"
    success, error = build_malwi_python(wrapper_path, base_python)
    if not success:
        print("failed")
        shutil.rmtree(venv_path, ignore_errors=True)
        print(COMPILE_ERROR_MSG.format(error=error), file=sys.stderr)
        return 1
    print("done")

    # Step 4: Replace Python binaries with wrapper
    print("  Installing sandbox wrapper...", end=" ", flush=True)
    _, errors = _replace_python_binaries(bin_dir, wrapper_path)
    wrapper_path.unlink(missing_ok=True)
    if errors:
        print("failed")
        for binary, err in errors:
            print(f"  {binary.name}: {err}", file=sys.stderr)
        return 1
    print("done")

    # Step 5: Install pip
    print("  Installing pip...", end=" ", flush=True)
    success, error = _install_pip(bin_dir)
    if not success:
        print("failed")
        print(f"Error: {error}", file=sys.stderr)
        shutil.rmtree(venv_path, ignore_errors=True)
        return 1
    print("done")

    # Step 6: Install malwi-box
    print("  Installing malwi-box...", end=" ", flush=True)
    success, error = _install_package(bin_dir, "malwi-box")
    if not success:
        print("failed")
        print(f"Error: {error}", file=sys.stderr)
        shutil.rmtree(venv_path, ignore_errors=True)
        return 1
    print("done")

    # Step 7: Copy wrapper to package directory (non-fatal)
    print("  Installing wrapper binary...", end=" ", flush=True)
    _copy_wrapper_to_package(bin_dir)

    _print_success_message(venv_path)
    return 0

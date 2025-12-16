import os
import re
import subprocess
import sys
import sysconfig

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

extra_compile_args = []
if sys.platform != "win32":
    extra_compile_args = ["-std=c++17"]

ext_module = Extension(
    "malwi_box._audit_hook",
    sources=["src/malwi_box/malwi_box.cpp"],
    language="c++",
    extra_compile_args=extra_compile_args,
)


def get_python_version() -> str:
    """Get the current Python major.minor version."""
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def get_config_version(ldflags: str) -> str | None:
    """Extract Python version from ldflags (e.g., -lpython3.10 -> 3.10)."""
    match = re.search(r'-lpython(\d+\.\d+)', ldflags)
    if match:
        return match.group(1)
    return None


def get_python_build_flags() -> dict[str, str] | None:
    """Get build flags directly from Python's sysconfig.

    This is a fallback when python3-config is unavailable or returns wrong flags.
    """
    include = sysconfig.get_path("include")
    libdir = sysconfig.get_config_var("LIBDIR") or ""
    version = get_python_version()

    cflags = f"-I{include}"
    ldflags = f"-lpython{version}"

    # Check for framework build on macOS
    if sys.platform == "darwin":
        framework = sysconfig.get_config_var("PYTHONFRAMEWORK")
        if framework:
            framework_prefix = sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX") or ""
            ldflags = f"-framework {framework}"
            if framework_prefix:
                ldflags = f"-F{framework_prefix} " + ldflags

    # Add common required libraries
    ldflags += " -ldl"
    if sys.platform == "darwin":
        ldflags += " -framework CoreFoundation"

    prefix = sysconfig.get_config_var("prefix") or ""

    if include and prefix:
        return {
            'cflags': cflags,
            'ldflags': ldflags,
            'lib_dir': libdir,
            'python_home': prefix,
        }
    return None


class CustomBuildExt(build_ext):
    """Custom build_ext that also builds the malwi_python wrapper for development.

    Note: The malwi_python binary is NOT included in wheels because it's
    platform/Python-specific. Instead, it's compiled during `malwi-box venv`
    for the target Python. This only builds for --inplace (development) builds.
    """

    def run(self):
        super().run()
        # Only build malwi_python for inplace/development builds
        if self.inplace:
            self.build_malwi_python()

    def build_malwi_python(self):
        """Build the malwi_python embedded interpreter wrapper for development."""
        src = "src/malwi_box/malwi_python.c"
        if not os.path.exists(src):
            return

        out_file = "src/malwi_box/malwi_python"

        # Get Python build flags using python3-config
        # Resolve symlinks to find the real Python installation directory
        real_executable = os.path.realpath(sys.executable)
        python_dir = os.path.dirname(real_executable)
        python_config = os.path.join(python_dir, "python3-config")
        if not os.path.exists(python_config):
            python_config = "python3-config"  # Fall back to PATH

        cflags = None
        ldflags = None
        use_fallback = False
        target_version = get_python_version()

        try:
            cflags = subprocess.check_output(
                [python_config, "--cflags"], text=True
            ).strip()
            ldflags = subprocess.check_output(
                [python_config, "--ldflags", "--embed"], text=True
            ).strip()

            # Validate that python3-config matches current Python version
            config_version = get_config_version(ldflags)
            if config_version and config_version != target_version:
                print(f"Warning: python3-config version mismatch!")
                print(f"  python3-config returns flags for Python {config_version}")
                print(f"  but current Python is {target_version}")
                print(f"  python3-config: {python_config}")
                print(f"  Trying fallback method...")
                use_fallback = True

        except (subprocess.CalledProcessError, FileNotFoundError):
            print("Warning: Could not get Python build flags from python3-config")
            use_fallback = True

        # Use fallback: get flags directly from sysconfig
        if use_fallback:
            fallback_flags = get_python_build_flags()
            if fallback_flags:
                cflags = fallback_flags['cflags']
                ldflags = fallback_flags['ldflags']
                lib_dir = fallback_flags['lib_dir']
                python_home = fallback_flags['python_home']
                print(f"Using fallback build flags for Python {target_version}")
            else:
                print("Warning: Fallback method also failed. Skipping malwi_python build.")
                print("Try: uv run python3 setup.py build_ext --inplace")
                return
        else:
            # Get the library directory for rpath
            lib_dir = sysconfig.get_config_var("LIBDIR")
            if not lib_dir:
                lib_dir = os.path.join(os.path.dirname(python_dir), "lib")

            python_home = sysconfig.get_config_var("prefix")
            if not python_home:
                python_home = os.path.dirname(python_dir)

        compiler = "clang" if sys.platform == "darwin" else "gcc"

        # Build command with rpath for finding libpython at runtime
        rpath_flag = f"-Wl,-rpath,{lib_dir}"
        lib_flag = f"-L{lib_dir}"
        python_home_define = f'-DDEFAULT_PYTHON_HOME=\\"{python_home}\\"'

        cmd = f'{compiler} {cflags} {python_home_define} -o "{out_file}" "{src}" {lib_flag} {ldflags} {rpath_flag}'

        print(f"Building malwi_python: {out_file}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Warning: Failed to build malwi_python: {result.stderr}")
        else:
            print(f"Built malwi_python: {out_file}")


setup(
    ext_modules=[ext_module],
    cmdclass={"build_ext": CustomBuildExt},
)

import os
import sys

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


class CustomBuildExt(build_ext):
    """Custom build_ext that also builds the malwi_python wrapper."""

    def run(self):
        super().run()
        self.build_malwi_python()

    def build_malwi_python(self):
        """Build the malwi_python embedded interpreter wrapper."""
        import shutil
        import subprocess
        import sysconfig

        src = "src/malwi_box/malwi_python.c"
        if not os.path.exists(src):
            return

        out_dir = os.path.join(self.build_lib, "malwi_box")
        os.makedirs(out_dir, exist_ok=True)
        out_file = os.path.join(out_dir, "malwi_python")

        # Also determine inplace location for --inplace builds
        inplace_file = "src/malwi_box/malwi_python"

        # Get Python build flags using python3-config
        # Resolve symlinks to find the real Python installation directory
        real_executable = os.path.realpath(sys.executable)
        python_dir = os.path.dirname(real_executable)
        python_config = os.path.join(python_dir, "python3-config")
        if not os.path.exists(python_config):
            python_config = "python3-config"  # Fall back to PATH

        try:
            cflags = subprocess.check_output(
                [python_config, "--cflags"], text=True
            ).strip()
            ldflags = subprocess.check_output(
                [python_config, "--ldflags", "--embed"], text=True
            ).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("Warning: Could not get Python build flags from python3-config")
            return

        # Get the library directory for rpath
        lib_dir = sysconfig.get_config_var("LIBDIR")
        if not lib_dir:
            # Fallback: use the directory containing the Python executable's lib
            lib_dir = os.path.join(os.path.dirname(python_dir), "lib")

        # Get Python home (prefix) to embed as default
        python_home = sysconfig.get_config_var("prefix")
        if not python_home:
            python_home = os.path.dirname(python_dir)

        compiler = "clang" if sys.platform == "darwin" else "gcc"

        # Build command with rpath for finding libpython at runtime
        if sys.platform == "darwin":
            rpath_flag = f"-Wl,-rpath,{lib_dir}"
        else:
            rpath_flag = f"-Wl,-rpath,{lib_dir}"

        # Add -L flag to specify library search path (python3-config may not include it)
        lib_flag = f"-L{lib_dir}"

        # Add compile-time define for default Python home
        python_home_define = f'-DDEFAULT_PYTHON_HOME=\\"{python_home}\\"'

        cmd = f'{compiler} {cflags} {python_home_define} -o "{out_file}" "{src}" {lib_flag} {ldflags} {rpath_flag}'

        print(f"Building malwi_python: {out_file}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Warning: Failed to build malwi_python: {result.stderr}")
        else:
            print(f"Built malwi_python: {out_file}")
            # Copy to inplace location (for editable installs and --inplace)
            if self.inplace or out_file != inplace_file:
                shutil.copy2(out_file, inplace_file)
                print(f"Copied malwi_python to: {inplace_file}")


setup(
    ext_modules=[ext_module],
    cmdclass={"build_ext": CustomBuildExt},
)

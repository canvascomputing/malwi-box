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
        import subprocess
        import sysconfig

        src = "src/malwi_box/malwi_python.c"
        if not os.path.exists(src):
            return

        out_dir = os.path.join(self.build_lib, "malwi_box")
        os.makedirs(out_dir, exist_ok=True)
        out_file = os.path.join(out_dir, "malwi_python")

        # Get Python build flags using python3-config
        # Try to find python3-config in the same directory as the Python executable
        python_dir = os.path.dirname(sys.executable)
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

        compiler = "clang" if sys.platform == "darwin" else "gcc"

        # Build command with rpath for finding libpython at runtime
        if sys.platform == "darwin":
            rpath_flag = f"-Wl,-rpath,{lib_dir}"
        else:
            rpath_flag = f"-Wl,-rpath,{lib_dir}"

        cmd = f'{compiler} {cflags} -o "{out_file}" "{src}" {ldflags} {rpath_flag}'

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

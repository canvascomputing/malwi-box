import sys

from setuptools import Extension, setup

extra_compile_args = []
if sys.platform != "win32":
    extra_compile_args = ["-std=c++17"]

ext_module = Extension(
    "malwi_box._audit_hook",
    sources=["src/malwi_box/malwi_box.cpp"],
    language="c++",
    extra_compile_args=extra_compile_args,
)

setup(ext_modules=[ext_module])

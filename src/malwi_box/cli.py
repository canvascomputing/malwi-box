import argparse
import os
import subprocess
import sys
import tempfile

SITECUSTOMIZE_TEMPLATE = """\
import sys

def _malwi_box_hook(event, args):
    print(f"[AUDIT] {event}: {args}", file=sys.stderr)

try:
    from malwi_box import install_hook
    install_hook(_malwi_box_hook)
except ImportError as e:
    print(f"[malwi-box] Warning: Could not import malwi_box: {e}", file=sys.stderr)
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a Python script with audit hooks active"
    )
    parser.add_argument("script", help="Python script to run")
    parser.add_argument("args", nargs="*", help="Arguments for the script")

    args = parser.parse_args()

    # Verify script exists
    if not os.path.isfile(args.script):
        print(f"Error: Script not found: {args.script}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write sitecustomize.py
        sitecustomize_path = os.path.join(tmpdir, "sitecustomize.py")
        with open(sitecustomize_path, "w") as f:
            f.write(SITECUSTOMIZE_TEMPLATE)

        # Prepare environment with tmpdir prepended to PYTHONPATH
        env = os.environ.copy()
        existing_path = env.get("PYTHONPATH", "")
        if existing_path:
            env["PYTHONPATH"] = f"{tmpdir}{os.pathsep}{existing_path}"
        else:
            env["PYTHONPATH"] = tmpdir

        # Run the target script
        cmd = [sys.executable, args.script] + args.args
        result = subprocess.run(cmd, env=env)

        return result.returncode


if __name__ == "__main__":
    sys.exit(main())

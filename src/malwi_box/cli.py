import argparse
import os
import subprocess
import sys
import tempfile

RUN_SITECUSTOMIZE_TEMPLATE = """\
import sys

def _malwi_box_hook(event, args):
    print(f"[AUDIT] {event}: {args}", file=sys.stderr)

try:
    from malwi_box import install_hook
    install_hook(_malwi_box_hook)
except ImportError as e:
    print(f"[malwi-box] Warning: Could not import malwi_box: {e}", file=sys.stderr)
"""

REVIEW_SITECUSTOMIZE_TEMPLATE = """\
import os
import sys

# Events triggered by the review hook itself that must be blocked to prevent recursion
_REVIEW_BLOCKLIST = {
    "builtins.input",
    "builtins.input/result",
}

def _malwi_box_hook(event, args):
    print(f"[AUDIT] {event}: {args}", file=sys.stderr)
    try:
        response = input("Allow? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\\nAborted.", file=sys.stderr)
        sys.stderr.flush()
        os._exit(130)
    if response != "y":
        print("Denied. Terminating.", file=sys.stderr)
        sys.stderr.flush()
        os._exit(1)

try:
    from malwi_box import install_hook
    install_hook(_malwi_box_hook, blocklist=_REVIEW_BLOCKLIST)
except ImportError as e:
    print(f"[malwi-box] Warning: Could not import malwi_box: {e}", file=sys.stderr)
"""


def _run_with_hook(script: str, script_args: list[str], template: str) -> int:
    """Run a script with the specified sitecustomize template."""
    if not os.path.isfile(script):
        print(f"Error: Script not found: {script}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmpdir:
        sitecustomize_path = os.path.join(tmpdir, "sitecustomize.py")
        with open(sitecustomize_path, "w") as f:
            f.write(template)

        env = os.environ.copy()
        existing_path = env.get("PYTHONPATH", "")
        if existing_path:
            env["PYTHONPATH"] = f"{tmpdir}{os.pathsep}{existing_path}"
        else:
            env["PYTHONPATH"] = tmpdir

        cmd = [sys.executable, script] + script_args
        try:
            result = subprocess.run(cmd, env=env)
            return result.returncode
        except KeyboardInterrupt:
            print("\nAborted.", file=sys.stderr)
            return 130


def run_command(args: argparse.Namespace) -> int:
    """Run script with passive audit logging."""
    return _run_with_hook(args.script, args.args, RUN_SITECUSTOMIZE_TEMPLATE)


def review_command(args: argparse.Namespace) -> int:
    """Run script with interactive approval for each audit event."""
    return _run_with_hook(args.script, args.args, REVIEW_SITECUSTOMIZE_TEMPLATE)


def main() -> int:
    parser = argparse.ArgumentParser(description="Python audit hook sandbox")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run subcommand
    run_parser = subparsers.add_parser("run", help="Run script with audit logging")
    run_parser.add_argument("script", help="Python script to run")
    run_parser.add_argument("args", nargs="*", help="Arguments for the script")

    # review subcommand
    review_parser = subparsers.add_parser(
        "review", help="Run script with interactive approval"
    )
    review_parser.add_argument("script", help="Python script to run")
    review_parser.add_argument("args", nargs="*", help="Arguments for the script")

    args = parser.parse_args()

    if args.command == "run":
        return run_command(args)
    elif args.command == "review":
        return review_command(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())

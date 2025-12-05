import argparse
import os
import subprocess
import sys
import tempfile

# Template for run mode: Uses BoxEngine to enforce config-based permissions
RUN_SITECUSTOMIZE_TEMPLATE = """\
import sys

try:
    from malwi_box import install_hook
    from malwi_box.engine import BoxEngine

    _engine = BoxEngine()

    def _malwi_box_hook(event, args):
        if not _engine.check_permission(event, args):
            sys.stderr.write(f"[malwi-box] BLOCKED: {event}: {args}\\n")
            sys.stderr.flush()
            import os
            os._exit(78)

    install_hook(_malwi_box_hook)
except ImportError as e:
    print(f"[malwi-box] Warning: Could not import malwi_box: {e}", file=sys.stderr)
"""

# Template for review mode: Interactive approval with decision recording
REVIEW_SITECUSTOMIZE_TEMPLATE = """\
import atexit
import os
import sys

# Events triggered by the review hook itself that must be blocked to prevent recursion
_REVIEW_BLOCKLIST = {
    "builtins.input",
    "builtins.input/result",
}

try:
    from malwi_box import install_hook
    from malwi_box.engine import BoxEngine

    _engine = BoxEngine()

    def _malwi_box_hook(event, args):
        # First check if already allowed by config
        if _engine.check_permission(event, args):
            return

        # Not in config - ask user
        print(f"[AUDIT] {event}: {args}", file=sys.stderr)
        try:
            response = input("Allow? [y/N/a(lways)]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\\nAborted.", file=sys.stderr)
            sys.stderr.flush()
            _engine.save_decisions()  # Save before exit
            os._exit(130)

        if response == "a":
            # Always allow - record decision
            details = {"event": event}
            if event == "open" and args:
                import os as _os
                from pathlib import Path as _Path
                details["path"] = str(args[0])
                details["mode"] = args[1] if len(args) > 1 else "r"
                # Track if this is a new file (for create vs modify)
                details["is_new_file"] = not _Path(args[0]).exists()
            elif event in ("subprocess.Popen", "os.system") and args:
                if event == "os.system":
                    details["command"] = str(args[0])
                else:
                    details["command"] = " ".join([str(args[0])] + [str(a) for a in (args[1] if len(args) > 1 else [])])
            elif event in ("os.putenv", "os.unsetenv") and args:
                details["key"] = str(args[0])
            elif event == "socket.getaddrinfo" and args:
                details["domain"] = str(args[0])
                if len(args) > 1 and args[1] is not None:
                    details["port"] = args[1]
            elif event == "socket.gethostbyname" and args:
                details["domain"] = str(args[0])
            _engine.record_decision(event, args, allowed=True, details=details)
        elif response != "y":
            print("Denied. Terminating.", file=sys.stderr)
            sys.stderr.flush()
            _engine.save_decisions()  # Save before exit
            os._exit(1)

    def _save_on_exit():
        _engine.save_decisions()

    atexit.register(_save_on_exit)
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

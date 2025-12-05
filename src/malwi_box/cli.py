import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _format_event(event: str, args: tuple) -> str:
    """Format audit event for human-readable output."""
    if event == "open" and args:
        path = args[0]
        mode = args[1] if len(args) > 1 else "r"
        if isinstance(path, bytes):
            path = path.decode("utf-8", errors="replace")
        is_write = any(c in str(mode) for c in "wax+")
        if is_write:
            action = "Create" if not Path(path).exists() else "Modify"
            return f"{action} file: {path}"
        return f"Read file: {path}"

    elif event == "os.putenv" and args:
        key = args[0].decode() if isinstance(args[0], bytes) else args[0]
        val = args[1].decode() if isinstance(args[1], bytes) else args[1]
        if len(val) > 50:
            val = val[:47] + "..."
        return f"Set env var: {key}={val}"

    elif event == "os.unsetenv" and args:
        key = args[0].decode() if isinstance(args[0], bytes) else args[0]
        return f"Unset env var: {key}"

    elif event == "socket.getaddrinfo" and args:
        host = args[0]
        port = args[1] if len(args) > 1 else ""
        if port:
            return f"DNS lookup: {host}:{port}"
        return f"DNS lookup: {host}"

    elif event == "socket.gethostbyname" and args:
        return f"DNS lookup: {args[0]}"

    elif event == "subprocess.Popen" and args:
        exe = args[0]
        cmd_args = args[1] if len(args) > 1 else []
        cmd = " ".join([str(exe)] + [str(a) for a in cmd_args])
        if len(cmd) > 80:
            cmd = cmd[:77] + "..."
        return f"Run command: {cmd}"

    elif event == "os.system" and args:
        cmd = str(args[0])
        if len(cmd) > 80:
            cmd = cmd[:77] + "..."
        return f"Run command: {cmd}"

    # Fallback for unknown events
    return f"{event}: {args}"

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

def _format_event(event, args):
    \"\"\"Format audit event for human-readable output.\"\"\"
    if event == "open" and args:
        path = args[0]
        mode = args[1] if len(args) > 1 else "r"
        if isinstance(path, bytes):
            path = path.decode("utf-8", errors="replace")
        is_write = any(c in str(mode) for c in "wax+")
        if is_write:
            from pathlib import Path as _Path
            action = "Create" if not _Path(path).exists() else "Modify"
            return f"{action} file: {path}"
        return f"Read file: {path}"

    elif event == "os.putenv" and args:
        key = args[0].decode() if isinstance(args[0], bytes) else args[0]
        val = args[1].decode() if isinstance(args[1], bytes) else args[1]
        if len(val) > 50:
            val = val[:47] + "..."
        return f"Set env var: {key}={val}"

    elif event == "os.unsetenv" and args:
        key = args[0].decode() if isinstance(args[0], bytes) else args[0]
        return f"Unset env var: {key}"

    elif event == "socket.getaddrinfo" and args:
        host = args[0]
        port = args[1] if len(args) > 1 else ""
        if port:
            return f"DNS lookup: {host}:{port}"
        return f"DNS lookup: {host}"

    elif event == "socket.gethostbyname" and args:
        return f"DNS lookup: {args[0]}"

    elif event == "subprocess.Popen" and args:
        exe = args[0]
        cmd_args = args[1] if len(args) > 1 else []
        cmd = " ".join([str(exe)] + [str(a) for a in cmd_args])
        if len(cmd) > 80:
            cmd = cmd[:77] + "..."
        return f"Run command: {cmd}"

    elif event == "os.system" and args:
        cmd = str(args[0])
        if len(cmd) > 80:
            cmd = cmd[:77] + "..."
        return f"Run command: {cmd}"

    # Fallback for unknown events
    return f"{event}: {args}"

try:
    from malwi_box import install_hook
    from malwi_box.engine import BoxEngine

    _engine = BoxEngine()

    def _malwi_box_hook(event, args):
        # First check if already allowed by config
        if _engine.check_permission(event, args):
            return

        # Not in config - ask user
        print(f"[AUDIT] {_format_event(event, args)}", file=sys.stderr)
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


def _run_with_hook(command: list[str], template: str) -> int:
    """Run a command with the specified sitecustomize template.

    Args:
        command: Command to run. Can be a script path or module name with args.
        template: The sitecustomize template to inject.

    If command[0] is a .py file, runs: python <script> <args>
    Otherwise, runs: python -m <module> <args>
    """
    if not command:
        print("Error: No command specified", file=sys.stderr)
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

        first = command[0]

        # If it looks like a Python script, run directly; otherwise use -m
        if first.endswith(".py") or os.path.isfile(first):
            cmd = [sys.executable] + command
        else:
            cmd = [sys.executable, "-m"] + command

        try:
            result = subprocess.run(cmd, env=env)
            return result.returncode
        except KeyboardInterrupt:
            print("\nAborted.", file=sys.stderr)
            return 130


def run_command(args: argparse.Namespace) -> int:
    """Run command with sandboxing."""
    command = list(args.command)
    review = args.review

    # Also check if --review is in command args (for convenience)
    if "--review" in command:
        command.remove("--review")
        review = True

    template = REVIEW_SITECUSTOMIZE_TEMPLATE if review else RUN_SITECUSTOMIZE_TEMPLATE
    return _run_with_hook(command, template)


def _ensure_pip() -> bool:
    """Ensure pip is available, installing via ensurepip if needed."""
    try:
        import pip  # noqa: F401
        return True
    except ImportError:
        pass

    # Try to bootstrap pip
    try:
        import ensurepip
        ensurepip.bootstrap(upgrade=True)
        return True
    except Exception as e:
        print(f"Error: Could not install pip: {e}", file=sys.stderr)
        return False


def install_command(args: argparse.Namespace) -> int:
    """Install package(s) with sandboxing using pip's Python API."""
    if not _ensure_pip():
        return 1

    # Build pip arguments
    pip_args = ["install"]
    if args.requirements:
        pip_args.extend(["-r", args.requirements])
    elif args.package:
        if args.pkg_version:
            pip_args.append(f"{args.package}=={args.pkg_version}")
        else:
            pip_args.append(args.package)
    else:
        print("Error: Must specify package or -r/--requirements", file=sys.stderr)
        return 1

    # Import and configure engine
    from malwi_box import install_hook
    from malwi_box.engine import BoxEngine

    engine = BoxEngine()

    if args.review:
        # Interactive review mode
        def review_hook(event, hook_args):
            if engine.check_permission(event, hook_args):
                return
            print(f"[AUDIT] {_format_event(event, hook_args)}", file=sys.stderr)
            try:
                response = input("Allow? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.", file=sys.stderr)
                sys.exit(130)
            if response != "y":
                print("Denied. Terminating.", file=sys.stderr)
                sys.exit(1)

        install_hook(review_hook, blocklist={"builtins.input", "builtins.input/result"})
    else:
        # Enforcement mode
        def enforce_hook(event, hook_args):
            if not engine.check_permission(event, hook_args):
                print(f"[malwi-box] BLOCKED: {_format_event(event, hook_args)}", file=sys.stderr)
                sys.exit(78)

        install_hook(enforce_hook)

    # Run pip
    from pip._internal.cli.main import main as pip_main
    return pip_main(pip_args)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Python audit hook sandbox",
        usage="%(prog)s {run,install} ...",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # run subcommand
    run_parser = subparsers.add_parser(
        "run",
        help="Run a Python script or module with sandboxing",
        usage="%(prog)s <script.py|module> [args...] [--review]",
    )
    run_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Python script or module to run",
    )
    run_parser.add_argument(
        "--review",
        action="store_true",
        help="Enable interactive approval mode",
    )

    # install subcommand
    install_parser = subparsers.add_parser(
        "install",
        help="Install Python packages with sandboxing",
        usage="%(prog)s <package> [--version VERSION] | -r <requirements.txt> [--review]",
    )
    install_parser.add_argument(
        "package",
        nargs="?",
        help="Package name to install",
    )
    install_parser.add_argument(
        "--version",
        dest="pkg_version",
        help="Package version to install",
    )
    install_parser.add_argument(
        "-r", "--requirements",
        dest="requirements",
        help="Install from requirements file",
    )
    install_parser.add_argument(
        "--review",
        action="store_true",
        help="Enable interactive approval mode",
    )

    args = parser.parse_args()

    if args.subcommand == "run":
        return run_command(args)
    elif args.subcommand == "install":
        return install_command(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())

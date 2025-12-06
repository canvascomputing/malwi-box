"""CLI for malwi-box sandbox."""

import argparse
import os
import subprocess
import sys
import tempfile

from malwi_box.formatting import format_event as _format_event  # noqa: F401

# Templates import the hook modules which auto-setup on import
RUN_SITECUSTOMIZE_TEMPLATE = (
    "from malwi_box.hooks.run_hook import setup_hook; setup_hook()"
)
REVIEW_SITECUSTOMIZE_TEMPLATE = (
    "from malwi_box.hooks.review_hook import setup_hook; setup_hook()"
)


def _run_with_hook(command: list[str], template: str) -> int:
    """Run a command with the specified sitecustomize template."""
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

    from malwi_box import extract_decision_details, format_event, install_hook
    from malwi_box.engine import BoxEngine

    engine = BoxEngine()

    if args.review:
        import atexit

        atexit.register(engine.save_decisions)
        session_allowed: set[tuple] = set()
        in_hook = False  # Recursion guard

        def make_hashable(obj):
            """Convert an object to a hashable form."""
            if isinstance(obj, (list, tuple)):
                return tuple(make_hashable(item) for item in obj)
            if isinstance(obj, dict):
                return tuple(sorted((k, make_hashable(v)) for k, v in obj.items()))
            return obj

        def review_hook(event, hook_args):
            nonlocal in_hook
            if in_hook:
                return  # Prevent recursion

            # Check if already approved this session
            key = (event, make_hashable(hook_args))
            if key in session_allowed:
                return

            in_hook = True
            try:
                if engine.check_permission(event, hook_args):
                    return

                print(f"[AUDIT] {format_event(event, hook_args)}", file=sys.stderr)
                try:
                    response = input("Allow? [Y/n]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\nAborted.", file=sys.stderr)
                    engine.save_decisions()
                    sys.exit(130)
                if response == "n":
                    print("Denied. Terminating.", file=sys.stderr)
                    engine.save_decisions()
                    sys.exit(1)

                session_allowed.add(key)
                details = extract_decision_details(event, hook_args)
                engine.record_decision(event, hook_args, allowed=True, details=details)
            finally:
                in_hook = False

        install_hook(review_hook, blocklist={"builtins.input", "builtins.input/result"})
    else:
        in_enforce_hook = False  # Recursion guard

        def enforce_hook(event, hook_args):
            nonlocal in_enforce_hook
            if in_enforce_hook:
                return

            in_enforce_hook = True
            try:
                if not engine.check_permission(event, hook_args):
                    msg = f"[malwi-box] BLOCKED: {format_event(event, hook_args)}"
                    print(msg, file=sys.stderr)
                    sys.exit(78)
            finally:
                in_enforce_hook = False

        install_hook(enforce_hook)

    from pip._internal.cli.main import main as pip_main
    return pip_main(pip_args)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Python audit hook sandbox",
        usage="%(prog)s {run,install} ...",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

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

    install_parser = subparsers.add_parser(
        "install",
        help="Install Python packages with sandboxing",
        usage="%(prog)s <package> [--version VER] | -r <file> [--review]",
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

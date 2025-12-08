"""CLI for malwi-box sandbox."""

import argparse
import os
import subprocess
import sys
import tempfile

from malwi_box import __version__

# Templates import the hook module which auto-setup on import
RUN_SITECUSTOMIZE_TEMPLATE = (
    "from malwi_box.hook import setup_run_hook; setup_run_hook()"
)
REVIEW_SITECUSTOMIZE_TEMPLATE = (
    "from malwi_box.hook import setup_review_hook; setup_review_hook()"
)
FORCE_SITECUSTOMIZE_TEMPLATE = (
    "from malwi_box.hook import setup_force_hook; setup_force_hook()"
)


def _select_template(review: bool, force: bool) -> str:
    """Select the appropriate sitecustomize template."""
    if force:
        return FORCE_SITECUSTOMIZE_TEMPLATE
    elif review:
        return REVIEW_SITECUSTOMIZE_TEMPLATE
    else:
        return RUN_SITECUSTOMIZE_TEMPLATE


def _setup_hook_env(template: str) -> tuple[str, dict[str, str]]:
    """Create sitecustomize.py and return (tmpdir, env) for hook injection.

    Note: Caller must manage the temporary directory lifecycle.
    """
    tmpdir = tempfile.mkdtemp()
    sitecustomize_path = os.path.join(tmpdir, "sitecustomize.py")
    with open(sitecustomize_path, "w") as f:
        f.write(template)

    env = os.environ.copy()
    existing_path = env.get("PYTHONPATH", "")
    if existing_path:
        env["PYTHONPATH"] = f"{tmpdir}{os.pathsep}{existing_path}"
    else:
        env["PYTHONPATH"] = tmpdir

    return tmpdir, env


def _run_with_hook_code(code: str, template: str) -> int:
    """Run Python code string with the specified sitecustomize template."""
    tmpdir, env = _setup_hook_env(template)
    try:
        cmd = [sys.executable, "-c", code]
        result = subprocess.run(cmd, env=env)
        return result.returncode
    except KeyboardInterrupt:
        return 130
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


def _run_with_hook(command: list[str], template: str) -> int:
    """Run a command with the specified sitecustomize template."""
    if not command:
        print("Error: No command specified", file=sys.stderr)
        return 1

    tmpdir, env = _setup_hook_env(template)
    try:
        first = command[0]
        if first.endswith(".py") or os.path.isfile(first):
            cmd = [sys.executable] + command
        else:
            cmd = [sys.executable, "-m"] + command

        result = subprocess.run(cmd, env=env)
        return result.returncode
    except KeyboardInterrupt:
        return 130
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)


def run_command(args: argparse.Namespace) -> int:
    """Run command with sandboxing."""
    command = list(args.command)
    review = args.review
    force = args.force

    if "--review" in command:
        command.remove("--review")
        review = True
    if "--force" in command:
        command.remove("--force")
        force = True

    template = _select_template(review, force)
    return _run_with_hook(command, template)


def eval_command(args: argparse.Namespace) -> int:
    """Execute Python code string with sandboxing."""
    template = _select_template(args.review, args.force)
    return _run_with_hook_code(args.code, template)


def _build_pip_args(args: argparse.Namespace) -> list[str] | None:
    """Build pip install arguments from CLI args. Returns None on error."""
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
        return None
    return pip_args


def install_command(args: argparse.Namespace) -> int:
    """Install package(s) with sandboxing using pip's Python API."""
    pip_args = _build_pip_args(args)
    if pip_args is None:
        return 1

    from pip._internal.cli.main import main as pip_main

    from malwi_box.engine import BoxEngine
    from malwi_box.hook import setup_review_hook, setup_run_hook

    engine = BoxEngine()

    if args.review:
        setup_review_hook(engine)
    else:
        setup_run_hook(engine)

    return pip_main(pip_args)


def config_create_command(args: argparse.Namespace) -> int:
    """Create a default config file."""
    from malwi_box import toml
    from malwi_box.engine import BoxEngine

    path = args.path
    if os.path.exists(path):
        print(f"Error: {path} already exists", file=sys.stderr)
        return 1

    engine = BoxEngine(config_path=path)
    config = engine._default_config()

    with open(path, "w") as f:
        toml.dump(config, f)

    print(f"Created {path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Python audit hook sandbox",
        usage="%(prog)s {run,eval,install,config} ...",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"%(prog)s {__version__}",
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
    run_parser.add_argument(
        "--force",
        action="store_true",
        help="Log violations without blocking",
    )

    eval_parser = subparsers.add_parser(
        "eval",
        help="Execute Python code string with sandboxing",
        usage="%(prog)s <code> [--review] [--force]",
    )
    eval_parser.add_argument(
        "code",
        help="Python code to execute",
    )
    eval_parser.add_argument(
        "--review",
        action="store_true",
        help="Enable interactive approval mode",
    )
    eval_parser.add_argument(
        "--force",
        action="store_true",
        help="Log violations without blocking",
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
        "-r",
        "--requirements",
        dest="requirements",
        help="Install from requirements file",
    )
    install_parser.add_argument(
        "--review",
        action="store_true",
        help="Enable interactive approval mode",
    )

    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_subparsers = config_parser.add_subparsers(
        dest="config_subcommand", required=True
    )

    create_parser = config_subparsers.add_parser(
        "create", help="Create default config file"
    )
    create_parser.add_argument(
        "--path",
        default=".malwi-box.toml",
        help="Path to config file (default: .malwi-box.toml)",
    )

    args = parser.parse_args()

    if args.subcommand == "run":
        return run_command(args)
    elif args.subcommand == "eval":
        return eval_command(args)
    elif args.subcommand == "install":
        return install_command(args)
    elif args.subcommand == "config" and args.config_subcommand == "create":
        return config_create_command(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())

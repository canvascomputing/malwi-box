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
FORCE_SITECUSTOMIZE_TEMPLATE = (
    "from malwi_box.hooks.force_hook import setup_hook; setup_hook()"
)


def _setup_hook_env(template: str) -> tuple[str, dict[str, str]]:
    """Create sitecustomize.py and return (tmpdir, env) for hook injection.

    Note: Caller must manage the temporary directory lifecycle.
    """
    import tempfile as tf

    tmpdir = tf.mkdtemp()
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
            return 130


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

    if force:
        template = FORCE_SITECUSTOMIZE_TEMPLATE
    elif review:
        template = REVIEW_SITECUSTOMIZE_TEMPLATE
    else:
        template = RUN_SITECUSTOMIZE_TEMPLATE
    return _run_with_hook(command, template)


def eval_command(args: argparse.Namespace) -> int:
    """Execute Python code string with sandboxing."""
    code = args.code

    if args.force:
        template = FORCE_SITECUSTOMIZE_TEMPLATE
    elif args.review:
        template = REVIEW_SITECUSTOMIZE_TEMPLATE
    else:
        template = RUN_SITECUSTOMIZE_TEMPLATE

    return _run_with_hook_code(code, template)


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
    from malwi_box.hooks import review_hook, run_hook

    engine = BoxEngine()

    if args.review:
        review_hook.setup_hook(engine)
    else:
        run_hook.setup_hook(engine)

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

"""CLI for malwi-box sandbox."""

import argparse
import os
import subprocess
import sys

from malwi_box import __version__


def _get_mode(args: argparse.Namespace) -> str:
    """Get the mode from args."""
    if getattr(args, "force", False):
        return "force"
    elif getattr(args, "review", False):
        return "review"
    return "run"


def run_command(args: argparse.Namespace) -> int:
    """Run command with sandboxing using wrapper."""
    from malwi_box.wrapper import cleanup_wrapper_bin_dir, setup_wrapper_bin_dir

    command = list(args.command)

    # Handle --review/--force in command args (legacy support)
    if "--review" in command:
        command.remove("--review")
        args.review = True
    if "--force" in command:
        command.remove("--force")
        args.force = True

    if not command:
        print("Error: No command specified", file=sys.stderr)
        return 1

    mode = _get_mode(args)
    config_path = getattr(args, "config_path", None)

    bin_dir, wrapper_env = setup_wrapper_bin_dir(mode, config_path)
    if bin_dir is None:
        print("Error: Wrapper not available", file=sys.stderr)
        return 1

    try:
        env = os.environ.copy()
        env.update(wrapper_env)
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

        # Build command
        first = command[0]
        if first.endswith(".py") or os.path.isfile(first):
            cmd = [str(bin_dir / "python")] + command
        else:
            cmd = [str(bin_dir / "python"), "-m"] + command

        result = subprocess.run(cmd, env=env)
        return result.returncode
    except KeyboardInterrupt:
        return 130
    finally:
        cleanup_wrapper_bin_dir(bin_dir)


def eval_command(args: argparse.Namespace) -> int:
    """Execute Python code string with sandboxing using wrapper."""
    from malwi_box.wrapper import cleanup_wrapper_bin_dir, setup_wrapper_bin_dir

    mode = _get_mode(args)
    config_path = getattr(args, "config_path", None)

    bin_dir, wrapper_env = setup_wrapper_bin_dir(mode, config_path)
    if bin_dir is None:
        print("Error: Wrapper not available", file=sys.stderr)
        return 1

    try:
        env = os.environ.copy()
        env.update(wrapper_env)
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

        cmd = [str(bin_dir / "python"), "-c", args.code]
        result = subprocess.run(cmd, env=env)
        return result.returncode
    except KeyboardInterrupt:
        return 130
    finally:
        cleanup_wrapper_bin_dir(bin_dir)


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
    """Install package(s) with sandboxing using wrapper injection.

    Sets up a temporary bin directory with malwi_python as python/python3,
    prepends it to PATH, and runs pip. All Python subprocesses will use
    the wrapped interpreter with the audit hook.
    """
    pip_args = _build_pip_args(args)
    if pip_args is None:
        return 1

    from malwi_box.wrapper import cleanup_wrapper_bin_dir, setup_wrapper_bin_dir

    mode = _get_mode(args)
    config_path = getattr(args, "config_path", None)

    bin_dir, wrapper_env = setup_wrapper_bin_dir(mode, config_path)
    if bin_dir is None:
        print("Error: Wrapper not available", file=sys.stderr)
        return 1

    try:
        # Prepare environment with wrapper in PATH
        env = os.environ.copy()
        env.update(wrapper_env)
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

        # Run pip using our wrapped python
        cmd = [str(bin_dir / "python"), "-m", "pip"] + pip_args
        result = subprocess.run(cmd, env=env)
        return result.returncode
    except KeyboardInterrupt:
        return 130
    finally:
        cleanup_wrapper_bin_dir(bin_dir)


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
        usage="%(prog)s {run,eval,pip,venv,config} ...",
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
        usage="%(prog)s <script.py|module> [args...] [--review] [--force] [--config PATH]",
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
    run_parser.add_argument(
        "--config",
        dest="config_path",
        help="Path to config file",
    )

    eval_parser = subparsers.add_parser(
        "eval",
        help="Execute Python code string with sandboxing",
        usage="%(prog)s <code> [--review] [--force] [--config PATH]",
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
    eval_parser.add_argument(
        "--config",
        dest="config_path",
        help="Path to config file",
    )

    # pip subcommand with install sub-subcommand
    pip_parser = subparsers.add_parser("pip", help="Pip commands with sandboxing")
    pip_subparsers = pip_parser.add_subparsers(dest="pip_subcommand", required=True)

    pip_install_parser = pip_subparsers.add_parser(
        "install",
        help="Install Python packages with sandboxing",
        usage="%(prog)s <package> [--version VER] | -r <file> [--review] [--force] [--config PATH]",
    )
    pip_install_parser.add_argument(
        "package",
        nargs="?",
        help="Package name to install",
    )
    pip_install_parser.add_argument(
        "--version",
        dest="pkg_version",
        help="Package version to install",
    )
    pip_install_parser.add_argument(
        "-r",
        "--requirements",
        dest="requirements",
        help="Install from requirements file",
    )
    pip_install_parser.add_argument(
        "--review",
        action="store_true",
        help="Enable interactive approval mode",
    )
    pip_install_parser.add_argument(
        "--force",
        action="store_true",
        help="Log violations without blocking",
    )
    pip_install_parser.add_argument(
        "--config",
        dest="config_path",
        help="Path to config file",
    )

    # venv subcommand
    venv_parser = subparsers.add_parser(
        "venv",
        help="Create a sandboxed virtual environment",
    )
    venv_parser.add_argument(
        "--path",
        default=".venv",
        help="Path for the venv (default: .venv)",
    )
    venv_parser.add_argument(
        "--config",
        dest="config_path",
        help="Path to config file",
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
    elif args.subcommand == "pip" and args.pip_subcommand == "install":
        return install_command(args)
    elif args.subcommand == "venv":
        from pathlib import Path

        from malwi_box.venv import create_sandboxed_venv

        return create_sandboxed_venv(
            Path(args.path),
            getattr(args, "config_path", None),
        )
    elif args.subcommand == "config" and args.config_subcommand == "create":
        return config_create_command(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())

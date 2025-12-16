"""Audit hook installation and mode implementations.

This module provides:
- Low-level hook installation API (install_hook, uninstall_hook)
- High-level mode setup (setup_run_hook, setup_force_hook, setup_review_hook)
- Shared utilities for logging and hook callbacks
"""

from __future__ import annotations

import atexit
import inspect
import os
import sys
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from malwi_box._audit_hook import (
    clear_callback,
    set_blocklist,
    set_callback,
    set_log_info_events,
)

if TYPE_CHECKING:
    from malwi_box.engine import BoxEngine


# =============================================================================
# ANSI Color Codes
# =============================================================================


class Color:
    """ANSI color codes for terminal output."""

    RED = "\033[91m"
    ORANGE = "\033[93m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    RESET = "\033[0m"
    # Line control: move to start of line and clear it
    # This ensures our output isn't overwritten by progress bars/spinners
    CLEAR_LINE = "\r\033[K"


# =============================================================================
# Low-level Hook API
# =============================================================================


def install_hook(
    callback: Callable[[str, tuple], None],
    blocklist: Iterable[str] | None = None,
) -> None:
    """Install an audit hook callback.

    Args:
        callback: A callable that takes (event: str, args: tuple).
                  The callback is invoked for every audit event raised
                  by the Python runtime.
        blocklist: Optional iterable of event names to skip (not passed to callback).
    """
    if blocklist is not None:
        set_blocklist(list(blocklist))
    set_callback(callback)


def uninstall_hook() -> None:
    """Clear the audit hook callback.

    Note: The underlying audit hook remains registered (per PEP 578,
    audit hooks cannot be removed), but the callback will no longer
    be invoked.
    """
    clear_callback()


def set_event_blocklist(blocklist: Iterable[str] | None) -> None:
    """Set a blocklist of event names to skip.

    Args:
        blocklist: An iterable of event names to block, or None to clear.
    """
    if blocklist is None:
        set_blocklist(None)
    else:
        set_blocklist(list(blocklist))


def _build_blocklist(
    engine: "BoxEngine", extra: Iterable[str] | None = None
) -> list[str]:
    """Build blocklist including info-only events if disabled in config.

    Args:
        engine: BoxEngine instance with config
        extra: Additional events to block (e.g., review mode blocklist)

    Returns:
        List of event names to block at the C++ level
    """
    from malwi_box.engine import INFO_ONLY_EVENTS

    blocklist = list(extra) if extra else []

    # If info events are disabled, add them to blocklist to skip C++ -> Python callback
    if not engine.config.get("log_info_events", True):
        blocklist.extend(INFO_ONLY_EVENTS)

    return blocklist


def _configure_info_events(engine: "BoxEngine") -> None:
    """Configure C++ level info event handling based on config.

    Args:
        engine: BoxEngine instance with config
    """
    log_info = engine.config.get("log_info_events", True)
    set_log_info_events(log_info)


# =============================================================================
# Shared Logging Helpers
# =============================================================================


def _log_violation(event: str, args: tuple, color: str) -> None:
    """Log a permission violation with specified color."""
    from malwi_box import format_event

    # Clear line first to avoid being overwritten by progress bars
    msg = f"{Color.CLEAR_LINE}{color}[malwi-box] {format_event(event, args)}{Color.RESET}\n"
    sys.stderr.write(msg)
    sys.stderr.flush()


def _log_blocked(event: str, args: tuple) -> None:
    """Log a blocked event (red color with 'Blocked:' prefix)."""
    from malwi_box import format_event

    # Clear line first to avoid being overwritten by progress bars
    msg = f"{Color.CLEAR_LINE}{Color.RED}[malwi-box] Blocked: {format_event(event, args)}{Color.RESET}\n"
    sys.stderr.write(msg)
    sys.stderr.flush()


def _prompt_approval() -> str:
    """Prompt for approval using direct terminal I/O.

    Uses /dev/tty to avoid conflicts with user code that may be
    writing to stdout (e.g., loading animations with \\r).
    Falls back to input() when stdin is piped (e.g., tests, CI).
    """
    # Clear line to ensure prompt is visible over progress bars
    prompt = f"{Color.CLEAR_LINE}Approve? [Y/n/i]: "

    # If stdin is piped, use input() to read from it
    if not sys.stdin.isatty():
        return input(prompt).strip().lower()

    try:
        with open("/dev/tty", "r") as tty_in, open("/dev/tty", "w") as tty_out:
            tty_out.write(prompt)
            tty_out.flush()
            return tty_in.readline().strip().lower()
    except OSError:
        # Fallback for environments without /dev/tty
        return input(prompt).strip().lower()


# =============================================================================
# Hook Callback Factory
# =============================================================================


def _create_hook_callback(
    engine: BoxEngine,
    on_violation: Callable[[str, tuple], None],
) -> Callable[[str, tuple], None]:
    """Create a hook callback with common logic.

    Args:
        engine: BoxEngine for permission checks
        on_violation: Called when permission is denied (event, args)

    Returns:
        Hook callback function with recursion guard
    """
    in_hook = False

    def hook(event: str, args: tuple) -> None:
        nonlocal in_hook
        if in_hook:
            return

        in_hook = True
        try:
            # Handle env var reads with unified classification
            if event in ("os.getenv", "os.environ.get"):
                var_name = args[0] if args else ""
                classification = engine.classify_env_var(var_name)
                if classification in ("silent", "info"):
                    return  # No blocking for safe/info env vars
                # "block" falls through to permission check

            if not engine.check_permission(event, args):
                on_violation(event, args)
        finally:
            in_hook = False

    return hook


# =============================================================================
# Run Mode (Enforcement)
# =============================================================================


def setup_run_hook(engine: BoxEngine | None = None) -> None:
    """Set up enforcement mode hook.

    Violations are blocked and the process exits with code 78.

    Args:
        engine: BoxEngine instance. If None, creates a new one.
    """
    from malwi_box.engine import BoxEngine

    if engine is None:
        engine = BoxEngine()

    _configure_info_events(engine)

    def on_violation(event: str, args: tuple) -> None:
        _log_blocked(event, args)
        os._exit(78)

    hook = _create_hook_callback(engine, on_violation)
    blocklist = _build_blocklist(engine)
    install_hook(hook, blocklist=blocklist if blocklist else None)


# =============================================================================
# Force Mode (Log Only)
# =============================================================================


def setup_force_hook(engine: BoxEngine | None = None) -> None:
    """Set up force mode hook.

    Violations are logged but execution continues.

    Args:
        engine: BoxEngine instance. If None, creates a new one.
    """
    from malwi_box.engine import BoxEngine

    if engine is None:
        engine = BoxEngine()

    _configure_info_events(engine)

    def on_violation(event: str, args: tuple) -> None:
        _log_violation(event, args, Color.YELLOW)

    hook = _create_hook_callback(engine, on_violation)
    blocklist = _build_blocklist(engine)
    install_hook(hook, blocklist=blocklist if blocklist else None)


# =============================================================================
# Review Mode (Interactive)
# =============================================================================

# Review mode blocklist - prevents recursion on input()
REVIEW_BLOCKLIST = frozenset({"builtins.input", "builtins.input/result"})

# Events that replace the current process - atexit handlers won't run
PROCESS_REPLACING_EVENTS = frozenset({"os.exec", "os.posix_spawn"})

# DNS resolution events - need to cache IPs when approved
DNS_EVENTS = frozenset(
    {
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.gethostbyaddr",
    }
)

# Event criticality classification for color coding
CRITICAL_EVENTS = frozenset(
    {
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.gethostbyaddr",
        "socket.connect",
        "socket.__new__",
        "subprocess.Popen",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
        "os.system",
        "ctypes.dlopen",
        "urllib.Request",
        "http.request",
    }
)


def _get_event_color(event: str, args: tuple, engine: BoxEngine | None = None) -> str:
    """Get color based on event criticality."""
    if event in CRITICAL_EVENTS:
        return Color.RED
    if event == "open" and args:
        path = args[0]
        if engine and isinstance(path, (str, bytes)):
            if isinstance(path, bytes):
                path = path.decode("utf-8", errors="replace")
            if engine._is_sensitive_path(path):
                return Color.RED
        mode = args[1] if len(args) > 1 else "r"
        if mode and any(c in mode for c in "wax+"):
            return Color.ORANGE
    if event in ("os.getenv", "os.environ.get") and args and engine:
        var_name = args[0]
        if isinstance(var_name, bytes):
            var_name = var_name.decode("utf-8", errors="replace")
        if engine._is_sensitive_env_var(var_name):
            return Color.RED
    return Color.YELLOW


def get_caller_info() -> list[tuple[str, int, str, str]]:
    """Get call stack excluding malwi-box internals.

    Returns:
        List of (filename, lineno, function, code_context) tuples.
    """
    stack = inspect.stack()
    result = []

    skip_paths = {"malwi_box", "sitecustomize.py"}

    for frame_info in stack:
        filename = frame_info.filename
        if any(skip in filename for skip in skip_paths):
            continue
        if "<" in filename:  # e.g., <frozen importlib._bootstrap>
            continue

        result.append(
            (
                filename,
                frame_info.lineno,
                frame_info.function,
                frame_info.code_context[0].strip() if frame_info.code_context else "",
            )
        )

    return result


def setup_review_hook(engine: BoxEngine | None = None) -> None:
    """Set up review mode hook.

    Violations prompt for interactive approval. Approved decisions
    are recorded for future runs.

    Args:
        engine: BoxEngine instance. If None, creates a new one.
    """
    from malwi_box import extract_decision_details, format_event
    from malwi_box.engine import BoxEngine
    from malwi_box.formatting import format_stack_trace

    if engine is None:
        engine = BoxEngine()

    _configure_info_events(engine)

    session_allowed: set[tuple] = set()
    in_hook = False

    def make_hashable(obj):
        """Convert an object to a hashable form."""
        if isinstance(obj, (list, tuple)):
            return tuple(make_hashable(item) for item in obj)
        if isinstance(obj, dict):
            return tuple(sorted((k, make_hashable(v)) for k, v in obj.items()))
        return obj

    def hook(event: str, args: tuple) -> None:
        nonlocal in_hook
        if in_hook:
            return

        # Handle env var reads with unified classification
        if event in ("os.getenv", "os.environ.get"):
            var_name = args[0] if args else ""
            classification = engine.classify_env_var(var_name)
            if classification in ("silent", "info"):
                return  # No blocking for safe/info env vars
            # "block" falls through to permission check

        # Check if already approved this session
        key = (event, make_hashable(args))
        if key in session_allowed:
            return

        in_hook = True
        try:
            if engine.check_permission(event, args):
                return

            color = _get_event_color(event, args, engine)
            msg = f"{color}[malwi-box] {format_event(event, args)}{Color.RESET}"
            print(msg, file=sys.stderr)

            # Prompt loop with inspect option
            while True:
                try:
                    response = _prompt_approval()
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{Color.YELLOW}Aborted{Color.RESET}", file=sys.stderr)
                    sys.stderr.flush()
                    engine.save_decisions()
                    os._exit(130)

                if response == "i":
                    caller_info = get_caller_info()
                    print(f"\n{format_stack_trace(caller_info)}\n", file=sys.stderr)
                    continue
                break

            if response == "n":
                print(f"{Color.YELLOW}Denied{Color.RESET}", file=sys.stderr)
                sys.stderr.flush()
                engine.save_decisions()
                os._exit(1)

            session_allowed.add(key)
            details = extract_decision_details(event, args)
            engine.record_decision(event, args, allowed=True, details=details)

            # For DNS events, cache resolved IPs so socket.connect works
            if event in DNS_EVENTS and args:
                host = args[0]
                port = args[1] if len(args) > 1 else None
                engine._cache_resolved_ips(host, port)

            # Save immediately after each approval
            engine.save_decisions()
        finally:
            in_hook = False

    def save_on_exit():
        engine.save_decisions()

    atexit.register(save_on_exit)
    blocklist = _build_blocklist(engine, REVIEW_BLOCKLIST)
    install_hook(hook, blocklist=blocklist if blocklist else None)

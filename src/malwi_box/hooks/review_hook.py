"""Review mode hook - interactive approval with decision recording.

This module is injected via sitecustomize.py when running in review mode.
It can also be imported directly for testing.
"""

import atexit
import inspect
import os
import sys

BLOCKLIST = {"builtins.input", "builtins.input/result"}

# ANSI color codes
RED = "\033[91m"
ORANGE = "\033[93m"
YELLOW = "\033[33m"
RESET = "\033[0m"

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

# Event criticality classification
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

WARNING_EVENTS = frozenset(
    {
        "os.putenv",
        "os.unsetenv",
    }
)


def get_event_color(event: str, args: tuple) -> str:
    """Get color based on event criticality."""
    if event in CRITICAL_EVENTS:
        return RED
    if event in WARNING_EVENTS:
        return ORANGE
    if event == "open" and len(args) > 1:
        mode = args[1] or "r"
        if any(c in mode for c in "wax+"):
            return ORANGE
    return YELLOW


def get_caller_info() -> list[tuple[str, int, str, str]]:
    """Get call stack excluding malwi-box internals.

    Returns list of (filename, lineno, function, code_context) tuples.
    """
    stack = inspect.stack()
    result = []

    # Skip frames from malwi-box itself
    skip_paths = {"malwi_box", "sitecustomize.py"}

    for frame_info in stack:
        filename = frame_info.filename
        # Skip internal frames
        if any(skip in filename for skip in skip_paths):
            continue
        # Skip frames from standard library audit hook machinery
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


def setup_hook(engine=None):
    """Set up the review hook.

    Args:
        engine: BoxEngine instance. If None, creates a new one.
    """
    from malwi_box import extract_decision_details, format_event, install_hook
    from malwi_box.engine import BoxEngine
    from malwi_box.formatting import format_stack_trace

    if engine is None:
        engine = BoxEngine()

    session_allowed: set[tuple] = set()
    in_hook = False  # Recursion guard

    def make_hashable(obj):
        """Convert an object to a hashable form."""
        if isinstance(obj, (list, tuple)):
            return tuple(make_hashable(item) for item in obj)
        if isinstance(obj, dict):
            return tuple(sorted((k, make_hashable(v)) for k, v in obj.items()))
        return obj

    def hook(event, args):
        nonlocal in_hook
        if in_hook:
            return  # Prevent recursion

        # Check if already approved this session
        key = (event, make_hashable(args))
        if key in session_allowed:
            return

        in_hook = True
        try:
            if engine.check_permission(event, args):
                return

            color = get_event_color(event, args)
            msg = f"{color}[malwi-box] {format_event(event, args)}{RESET}"
            print(msg, file=sys.stderr)

            # Prompt loop with inspect option
            while True:
                try:
                    response = input("Approve? [Y/n/i]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{YELLOW}Aborted{RESET}", file=sys.stderr)
                    sys.stderr.flush()
                    engine.save_decisions()
                    os._exit(130)

                if response == "i":
                    caller_info = get_caller_info()
                    print(f"\n{format_stack_trace(caller_info)}\n", file=sys.stderr)
                    continue  # Re-prompt
                break  # Y, n, or empty

            if response == "n":
                print(f"{YELLOW}Denied{RESET}", file=sys.stderr)
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

            # Process-replacing events need immediate save (atexit won't run)
            if event in PROCESS_REPLACING_EVENTS:
                engine.save_decisions()
        finally:
            in_hook = False

    def save_on_exit():
        engine.save_decisions()

    atexit.register(save_on_exit)
    install_hook(hook, blocklist=BLOCKLIST)

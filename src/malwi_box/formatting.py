"""Formatting utilities for audit events."""

from pathlib import Path


def format_event(event: str, args: tuple) -> str:
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


def extract_decision_details(event: str, args: tuple) -> dict:
    """Extract details from an audit event for decision recording."""
    details = {"event": event}

    if event == "open" and args:
        details["path"] = str(args[0])
        details["mode"] = args[1] if len(args) > 1 and args[1] is not None else "r"
        details["is_new_file"] = not Path(args[0]).exists()
    elif event in ("subprocess.Popen", "os.system") and args:
        if event == "os.system":
            details["command"] = str(args[0])
        else:
            details["command"] = " ".join(
                [str(args[0])] + [str(a) for a in (args[1] if len(args) > 1 else [])]
            )
    elif event in ("os.putenv", "os.unsetenv") and args:
        details["key"] = str(args[0])
    elif event == "socket.getaddrinfo" and args:
        details["domain"] = str(args[0])
        if len(args) > 1 and args[1] is not None:
            details["port"] = args[1]
    elif event == "socket.gethostbyname" and args:
        details["domain"] = str(args[0])

    return details

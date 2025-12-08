"""Formatting utilities for audit events."""

import os
from pathlib import Path

MAX_VALUE_LEN = 50
MAX_CMD_LEN = 80


def _decode(value) -> str:
    """Decode bytes to string if needed."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _truncate(s: str, max_len: int) -> str:
    """Truncate string with ellipsis if too long."""
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def _build_command(exe, cmd_args) -> str:
    """Build command string from executable and args.

    cmd_args is typically argv which includes the program name as first element.
    """
    if cmd_args:
        return " ".join(str(a) for a in cmd_args)
    return str(exe)


def format_event(event: str, args: tuple) -> str:
    """Format audit event for human-readable output."""
    if not args:
        return f"{event}: {args}"

    if event == "open":
        path = _decode(args[0])
        mode = args[1] if len(args) > 1 else "r"
        is_write = any(c in str(mode) for c in "wax+")
        if is_write:
            action = "Create" if not Path(path).exists() else "Modify"
            return f"{action} file: {path}"
        return f"Read file: {path}"

    if event == "os.putenv":
        key = _decode(args[0])
        val = _truncate(_decode(args[1]), MAX_VALUE_LEN)
        return f"Set env var: {key}={val}"

    if event == "os.unsetenv":
        return f"Unset env var: {_decode(args[0])}"

    if event in ("os.remove", "os.unlink"):
        path = _decode(args[0])
        return f"Delete file: {path}"

    if event in ("os.getenv", "os.environ.get"):
        key = _decode(args[0])
        return f"Read env var: {key}"

    if event == "socket.getaddrinfo":
        host = args[0]
        port = args[1] if len(args) > 1 else ""
        return f"DNS lookup: {host}:{port}" if port else f"DNS lookup: {host}"

    if event == "socket.gethostbyname":
        return f"DNS lookup: {args[0]}"

    if event in ("socket.gethostbyname_ex", "socket.gethostbyaddr"):
        return f"DNS lookup: {args[0]}"

    if event == "socket.connect":
        # args: (socket, address) where address is (host, port)
        if len(args) >= 2 and isinstance(args[1], tuple):
            host = args[1][0]
            port = args[1][1] if len(args[1]) > 1 else None
            if port:
                return f"Connect: {host}:{port}"
            return f"Connect: {host}"
        return f"Connect: {args}"

    if event == "subprocess.Popen":
        cmd_args = args[1] if len(args) > 1 else []
        cmd = _truncate(_build_command(args[0], cmd_args), MAX_CMD_LEN)
        return f"Execute: {cmd}"

    if event == "os.system":
        cmd = _truncate(str(args[0]), MAX_CMD_LEN)
        return f"Shell: {cmd}"

    if event == "os.exec":
        exe = args[0] if args else "?"
        return f"Exec: {exe}"

    if event == "os.spawn":
        exe = args[1] if len(args) > 1 else "?"
        return f"Spawn: {exe}"

    if event == "os.posix_spawn":
        exe = args[0] if args else "?"
        return f"Posix spawn: {exe}"

    if event == "ctypes.dlopen":
        lib = args[0] if args else "?"
        return f"Load library: {lib}"

    if event == "urllib.Request":
        url = args[0] if args else "?"
        method = args[3] if len(args) > 3 and args[3] else None
        if method is None:
            # Infer method from data presence
            data = args[1] if len(args) > 1 else None
            method = "POST" if data else "GET"
        return f"HTTP {method}: {_truncate(str(url), MAX_CMD_LEN)}"

    if event == "http.request":
        url = args[0] if args else "?"
        method = args[1] if len(args) > 1 else "GET"
        return f"HTTP {method}: {_truncate(str(url), MAX_CMD_LEN)}"

    # Info-only events (encoding/crypto)
    if event == "encoding.base64":
        operation = args[0] if args else "unknown"
        return f"Base64: {operation}"

    if event == "crypto.cipher":
        operation = args[0] if args else "unknown"
        action = "Encrypt" if "encrypt" in str(operation) else "Decrypt"
        return f"Cipher: {action}"

    if event == "crypto.fernet":
        operation = args[0] if args else "unknown"
        return f"Fernet: {operation}"

    # Deserialization events
    if event == "pickle.find_class":
        module = args[0] if args else "?"
        cls = args[1] if len(args) > 1 else "?"
        return f"Pickle: {module}.{cls}"

    if event == "marshal.loads":
        return "Marshal: loads"

    # Archive events
    if event == "shutil.unpack_archive":
        filename = args[0] if args else "?"
        extract_dir = args[1] if len(args) > 1 else "?"
        fmt = args[2] if len(args) > 2 else "auto"
        return f"Unpack: {filename} -> {extract_dir} ({fmt})"

    # Crypto algorithm events
    if event == "crypto.hmac":
        algo = args[0] if args else "?"
        return f"HMAC: {algo}"

    if event == "crypto.kdf":
        algo = args[0] if args else "?"
        return f"KDF: {algo}"

    if event == "crypto.rsa":
        key_size = args[0] if args else "?"
        op = args[1] if len(args) > 1 else "?"
        return f"RSA: {op} ({key_size} bits)"

    if event == "crypto.aes":
        mode = args[0] if args else "?"
        op = args[1] if len(args) > 1 else "?"
        return f"AES: {op} ({mode})"

    if event == "crypto.chacha20":
        op = args[0] if args else "?"
        return f"ChaCha20: {op}"

    # Random events
    if event == "secrets.token":
        size = args[0] if args else "?"
        return f"SecureRandom: {size} bytes"

    # Encoding & compression events
    if event == "encoding.hex":
        op = args[0] if args else "?"
        return f"Hex: {op}"

    if event == "encoding.zlib":
        op = args[0] if args else "?"
        return f"Zlib: {op}"

    if event == "encoding.gzip":
        op = args[0] if args else "?"
        return f"Gzip: {op}"

    if event == "encoding.bz2":
        op = args[0] if args else "?"
        return f"Bz2: {op}"

    if event == "encoding.lzma":
        op = args[0] if args else "?"
        return f"LZMA: {op}"

    if event == "socket.__new__":
        # Raw socket creation - args: (family, type, proto)
        import socket

        if len(args) >= 2 and args[1] == socket.SOCK_RAW:
            return "Raw socket creation"
        return f"Socket: {args}"

    return f"{event}: {args}"


def extract_decision_details(event: str, args: tuple) -> dict:
    """Extract details from an audit event for decision recording."""
    details = {"event": event}

    if not args:
        return details

    if event == "open":
        details["path"] = str(args[0])
        details["mode"] = args[1] if len(args) > 1 and args[1] is not None else "r"
        details["is_new_file"] = not Path(args[0]).exists()

    elif event == "os.system":
        details["command"] = str(args[0])

    elif event == "subprocess.Popen":
        cmd_args = args[1] if len(args) > 1 else []
        details["command"] = _build_command(args[0], cmd_args)
        details["executable"] = str(args[0]) if args[0] else ""

    elif event == "os.exec":
        details["executable"] = str(args[0]) if args else ""

    elif event == "os.spawn":
        details["executable"] = str(args[1]) if len(args) > 1 else ""

    elif event == "os.posix_spawn":
        details["executable"] = str(args[0]) if args else ""

    elif event == "ctypes.dlopen":
        details["library"] = str(args[0]) if args else ""

    elif event in ("os.putenv", "os.unsetenv", "os.getenv", "os.environ.get"):
        key = args[0]
        details["key"] = key.decode() if isinstance(key, bytes) else str(key)

    elif event == "socket.getaddrinfo":
        details["domain"] = str(args[0])
        if len(args) > 1 and args[1] is not None:
            details["port"] = args[1]

    elif event in (
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.gethostbyaddr",
    ):
        details["domain"] = str(args[0])

    elif event == "socket.connect":
        # args: (socket, address) where address is (host, port)
        if len(args) >= 2 and isinstance(args[1], tuple):
            details["host"] = str(args[1][0])
            if len(args[1]) > 1:
                details["port"] = args[1][1]

    elif event == "urllib.Request":
        # args: (url, data, headers, method)
        details["url"] = str(args[0]) if args else ""
        if len(args) > 3 and args[3]:
            details["method"] = str(args[3])
        else:
            # Infer method from data presence
            data = args[1] if len(args) > 1 else None
            details["method"] = "POST" if data else "GET"

    elif event == "http.request":
        # args: (url, method)
        details["url"] = str(args[0]) if args else ""
        details["method"] = str(args[1]) if len(args) > 1 else "GET"

    elif event == "socket.__new__":
        # args: (family, type, proto)
        import socket

        if len(args) >= 2:
            is_raw = args[1] == socket.SOCK_RAW
            details["socket_type"] = "SOCK_RAW" if is_raw else str(args[1])

    return details


def format_stack_trace(caller_info: list) -> str:
    """Format caller info as a minimal stack trace.

    Top frame gets arrow and code context. Rest are compact.

    Args:
        caller_info: List of (filename, lineno, function, code_context) tuples.

    Returns:
        Formatted stack trace string.
    """
    if not caller_info:
        return "  (no user code in stack)"

    lines = []
    for i, (filename, lineno, func, code) in enumerate(caller_info[:5]):
        # Use basename for cleaner output
        basename = os.path.basename(filename)

        if i == 0:
            # Top frame: arrow + code context
            lines.append(f"  → {basename}:{lineno} in {func}")
            if code:
                lines.append(f"      {code}")
        else:
            # Other frames: minimal
            lines.append(f"    {basename}:{lineno} in {func}")

    return "\n".join(lines)

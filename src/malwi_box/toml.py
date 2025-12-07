"""Minimal TOML reading and writing for malwi-box config.

Zero dependencies - no tomllib/tomli required.
Supports the subset of TOML used by .malwi-box.toml:
- String values
- Arrays of strings
- Arrays with inline tables { key = "value" }
"""

import re


class TOMLError(Exception):
    """Error parsing TOML."""


def _parse_string(s: str, pos: int) -> tuple[str, int]:
    """Parse a quoted string starting at pos, return (value, new_pos)."""
    if s[pos] != '"':
        raise TOMLError(f"Expected '\"' at position {pos}")
    pos += 1
    result = []
    while pos < len(s):
        c = s[pos]
        if c == '"':
            return "".join(result), pos + 1
        elif c == "\\":
            pos += 1
            if pos >= len(s):
                raise TOMLError("Unexpected end of string")
            esc = s[pos]
            if esc == "n":
                result.append("\n")
            elif esc == "t":
                result.append("\t")
            elif esc == "\\":
                result.append("\\")
            elif esc == '"':
                result.append('"')
            else:
                result.append(esc)
            pos += 1
        else:
            result.append(c)
            pos += 1
    raise TOMLError("Unterminated string")


def _skip_whitespace(s: str, pos: int) -> int:
    """Skip whitespace and comments."""
    while pos < len(s):
        if s[pos] in " \t\r":
            pos += 1
        elif s[pos] == "#":
            while pos < len(s) and s[pos] != "\n":
                pos += 1
        else:
            break
    return pos


def _parse_inline_table(s: str, pos: int) -> tuple[dict, int]:
    """Parse inline table { key = "value", ... }."""
    if s[pos] != "{":
        raise TOMLError(f"Expected '{{' at position {pos}")
    pos += 1
    result = {}
    while pos < len(s):
        pos = _skip_whitespace(s, pos)
        if s[pos] == "}":
            return result, pos + 1
        # Parse key
        match = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)", s[pos:])
        if not match:
            raise TOMLError(f"Expected key at position {pos}")
        key = match.group(1)
        pos += len(key)
        pos = _skip_whitespace(s, pos)
        if s[pos] != "=":
            raise TOMLError(f"Expected '=' at position {pos}")
        pos += 1
        pos = _skip_whitespace(s, pos)
        value, pos = _parse_string(s, pos)
        result[key] = value
        pos = _skip_whitespace(s, pos)
        if s[pos] == ",":
            pos += 1
        elif s[pos] != "}":
            raise TOMLError(f"Expected ',' or '}}' at position {pos}")
    raise TOMLError("Unterminated inline table")


def _parse_array(s: str, pos: int) -> tuple[list, int]:
    """Parse array [ ... ]."""
    if s[pos] != "[":
        raise TOMLError(f"Expected '[' at position {pos}")
    pos += 1
    result = []
    while pos < len(s):
        pos = _skip_whitespace(s, pos)
        if s[pos] == "\n":
            pos += 1
            continue
        if s[pos] == "]":
            return result, pos + 1
        if s[pos] == '"':
            value, pos = _parse_string(s, pos)
            result.append(value)
        elif s[pos] == "{":
            value, pos = _parse_inline_table(s, pos)
            result.append(value)
        else:
            raise TOMLError(f"Unexpected character '{s[pos]}' at position {pos}")
        pos = _skip_whitespace(s, pos)
        if s[pos] == "\n":
            pos += 1
            continue
        if s[pos] == ",":
            pos += 1
        elif s[pos] != "]":
            raise TOMLError(f"Expected ',' or ']' at position {pos}")
    raise TOMLError("Unterminated array")


def loads(s: str) -> dict:
    """Parse TOML string into dict."""
    result = {}
    pos = 0
    while pos < len(s):
        pos = _skip_whitespace(s, pos)
        if pos >= len(s):
            break
        if s[pos] == "\n":
            pos += 1
            continue
        # Parse key
        match = re.match(r"([a-zA-Z_][a-zA-Z0-9_-]*)", s[pos:])
        if not match:
            if s[pos] == "#":
                while pos < len(s) and s[pos] != "\n":
                    pos += 1
                continue
            raise TOMLError(f"Expected key at position {pos}: {s[pos : pos + 20]}")
        key = match.group(1)
        pos += len(key)
        pos = _skip_whitespace(s, pos)
        if pos >= len(s) or s[pos] != "=":
            raise TOMLError(f"Expected '=' after key '{key}'")
        pos += 1
        pos = _skip_whitespace(s, pos)
        # Parse value
        if s[pos] == '"':
            value, pos = _parse_string(s, pos)
        elif s[pos] == "[":
            value, pos = _parse_array(s, pos)
        elif s[pos : pos + 4] == "true":
            value = True
            pos += 4
        elif s[pos : pos + 5] == "false":
            value = False
            pos += 5
        else:
            raise TOMLError(f"Unexpected value at position {pos}")
        result[key] = value
        # Skip to end of line
        while pos < len(s) and s[pos] != "\n":
            if s[pos] in " \t":
                pos += 1
            elif s[pos] == "#":
                while pos < len(s) and s[pos] != "\n":
                    pos += 1
            else:
                break
        if pos < len(s) and s[pos] == "\n":
            pos += 1
    return result


def load(f) -> dict:
    """Load TOML from file object."""
    return loads(f.read())


def _escape_string(s: str) -> str:
    """Escape a string for TOML."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def dump(config: dict, f) -> None:
    """Write config dict as TOML to file object."""
    for key, value in config.items():
        if isinstance(value, list):
            if not value:
                f.write(f"{key} = []\n")
            else:
                f.write(f"{key} = [\n")
                for item in value:
                    if isinstance(item, dict):
                        pairs = ", ".join(
                            f'{k} = "{_escape_string(v)}"' for k, v in item.items()
                        )
                        f.write(f"  {{ {pairs} }},\n")
                    else:
                        f.write(f'  "{_escape_string(item)}",\n')
                f.write("]\n")
        elif isinstance(value, str):
            f.write(f'{key} = "{_escape_string(value)}"\n')
        elif isinstance(value, bool):
            f.write(f"{key} = {str(value).lower()}\n")
        elif isinstance(value, (int, float)):
            f.write(f"{key} = {value}\n")
        f.write("\n")


def dumps(config: dict) -> str:
    """Write config dict as TOML string."""
    import io

    f = io.StringIO()
    dump(config, f)
    return f.getvalue()

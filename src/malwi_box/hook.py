from collections.abc import Callable, Iterable

from malwi_box._audit_hook import (
    clear_callback,
    set_blocklist,
    set_callback,
)


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

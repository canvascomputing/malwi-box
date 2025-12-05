from collections.abc import Callable

from malwi_box._audit_hook import clear_callback, set_callback


def install_hook(callback: Callable[[str, tuple], None]) -> None:
    """Install an audit hook callback.

    Args:
        callback: A callable that takes (event: str, args: tuple).
                  The callback is invoked for every audit event raised
                  by the Python runtime.
    """
    set_callback(callback)


def uninstall_hook() -> None:
    """Clear the audit hook callback.

    Note: The underlying audit hook remains registered (per PEP 578,
    audit hooks cannot be removed), but the callback will no longer
    be invoked.
    """
    clear_callback()

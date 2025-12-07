"""Force mode hook - log violations without blocking.

This module is injected via sitecustomize.py when running with --force.
It logs operations that would be blocked but allows execution to continue.
"""

import sys

# ANSI color codes
YELLOW = "\033[33m"
RESET = "\033[0m"


def setup_hook(engine=None):
    """Set up the force (log-only) hook.

    Args:
        engine: BoxEngine instance. If None, creates a new one.
    """
    from malwi_box import format_event, install_hook
    from malwi_box.engine import BoxEngine

    if engine is None:
        engine = BoxEngine()

    in_hook = False  # Recursion guard

    def hook(event, args):
        nonlocal in_hook
        if in_hook:
            return

        in_hook = True
        try:
            if not engine.check_permission(event, args):
                msg = f"{YELLOW}[malwi-box] {format_event(event, args)}{RESET}\n"
                sys.stderr.write(msg)
                sys.stderr.flush()
                # No os._exit() - let execution continue
        finally:
            in_hook = False

    install_hook(hook)

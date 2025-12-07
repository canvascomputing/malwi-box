"""Run mode hook - config-based permission enforcement.

This module is injected via sitecustomize.py when running in enforcement mode.
It can also be imported directly for testing.
"""

import os
import sys

# ANSI color codes
RED = "\033[91m"
RESET = "\033[0m"


def setup_hook(engine=None):
    """Set up the enforcement hook.

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
                msg = f"{RED}[malwi-box] Blocked: {format_event(event, args)}{RESET}\n"
                sys.stderr.write(msg)
                sys.stderr.flush()
                os._exit(78)
        finally:
            in_hook = False

    install_hook(hook)

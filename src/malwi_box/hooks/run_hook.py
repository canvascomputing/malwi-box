"""Run mode hook - config-based permission enforcement.

This module is injected via sitecustomize.py when running in enforcement mode.
It can also be imported directly for testing.
"""

import os
import sys


def setup_hook():
    """Set up the enforcement hook. Called automatically when used as sitecustomize."""
    try:
        from malwi_box import format_event, install_hook
        from malwi_box.engine import BoxEngine
    except ImportError as e:
        print(f"[malwi-box] Warning: Could not import malwi_box: {e}", file=sys.stderr)
        return

    engine = BoxEngine()

    def hook(event, args):
        if not engine.check_permission(event, args):
            sys.stderr.write(f"[malwi-box] BLOCKED: {format_event(event, args)}\n")
            sys.stderr.flush()
            os._exit(78)

    install_hook(hook)


# Auto-setup when imported as sitecustomize
if __name__ != "__main__":
    setup_hook()

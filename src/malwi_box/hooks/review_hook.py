"""Review mode hook - interactive approval with decision recording.

This module is injected via sitecustomize.py when running in review mode.
It can also be imported directly for testing.
"""

import atexit
import os
import sys

BLOCKLIST = {"builtins.input", "builtins.input/result"}


def setup_hook(engine=None):
    """Set up the review hook.

    Args:
        engine: BoxEngine instance. If None, creates a new one.
    """
    from malwi_box import extract_decision_details, format_event, install_hook
    from malwi_box.engine import BoxEngine

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

            print(f"[AUDIT] {format_event(event, args)}", file=sys.stderr)
            try:
                response = input("Allow? [Y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.", file=sys.stderr)
                sys.stderr.flush()
                engine.save_decisions()
                os._exit(130)

            if response == "n":
                print("Denied. Terminating.", file=sys.stderr)
                sys.stderr.flush()
                engine.save_decisions()
                os._exit(1)

            session_allowed.add(key)
            details = extract_decision_details(event, args)
            engine.record_decision(event, args, allowed=True, details=details)
        finally:
            in_hook = False

    def save_on_exit():
        engine.save_decisions()

    atexit.register(save_on_exit)
    install_hook(hook, blocklist=BLOCKLIST)


# Auto-setup when imported as sitecustomize
if __name__ != "__main__":
    setup_hook()

import os
import tempfile

import pytest

from malwi_box import install_hook, uninstall_hook


def test_install_and_capture_open_event():
    """Test that audit hooks capture file open events."""
    events = []

    def hook(event, args):
        if event == "open":
            events.append(event)

    install_hook(hook)
    # Open a file to trigger the 'open' event
    with tempfile.NamedTemporaryFile() as f:
        pass
    uninstall_hook()

    assert len(events) >= 1
    assert events[0] == "open"


def test_uninstall_stops_capturing():
    """Test that uninstall_hook stops the callback from being invoked."""
    events = []

    def hook(event, args):
        if event == "os.getenv":
            events.append(event)

    install_hook(hook)
    os.getenv("TEST_UNINSTALL_1")

    uninstall_hook()
    # Count AFTER uninstall completes
    count_after_uninstall = len(events)

    os.getenv("TEST_UNINSTALL_2")
    count_after_getenv = len(events)

    # No new events should be captured after uninstall completes
    assert count_after_getenv == count_after_uninstall


def test_callback_receives_event_and_args():
    """Test that callback receives correct event type and args tuple."""
    captured = []

    def hook(event, args):
        captured.append((event, args))

    install_hook(hook)
    os.getenv("TEST_CALLBACK_ARGS")
    uninstall_hook()

    # Find the os.getenv event
    getenv_events = [(e, a) for e, a in captured if e == "os.getenv"]
    assert len(getenv_events) >= 1

    event, args = getenv_events[0]
    assert event == "os.getenv"
    assert isinstance(args, tuple)
    assert args[0] == "TEST_CALLBACK_ARGS"


def test_callback_must_be_callable():
    """Test that set_callback raises TypeError for non-callable."""
    with pytest.raises(TypeError):
        install_hook("not a callable")


def test_only_security_events_passed_to_callback():
    """Test that only security-relevant events are passed to callback.

    Events like 'exec', 'import', 'compile' are filtered out at the C level
    for performance. Only events in the ALLOWED_EVENTS list are passed.
    """
    events = set()

    def hook(event, args):
        events.add(event)

    install_hook(hook)
    # Trigger various events
    exec("x = 1")  # 'exec' event - NOT in allowlist
    os.getenv("TEST_VAR")  # 'os.getenv' event - IN allowlist
    uninstall_hook()

    # 'exec' should NOT be in captured events (filtered at C level)
    assert "exec" not in events
    # 'os.getenv' SHOULD be in captured events
    assert "os.getenv" in events


def test_os_getenv_fires_event():
    """Test that os.getenv triggers an os.getenv audit event."""
    import os

    events = []

    def hook(event, args):
        if event == "os.getenv":
            events.append((event, args))

    install_hook(hook)
    os.getenv("TEST_VAR_GETENV")
    uninstall_hook()

    assert len(events) == 1
    assert events[0][0] == "os.getenv"
    assert events[0][1][0] == "TEST_VAR_GETENV"


def test_os_environ_get_fires_event():
    """Test that os.environ.get triggers an os.environ.get audit event."""
    import os

    events = []

    def hook(event, args):
        if event == "os.environ.get":
            events.append((event, args))

    install_hook(hook)
    os.environ.get("TEST_VAR_ENVIRON_GET")
    uninstall_hook()

    assert len(events) == 1
    assert events[0][0] == "os.environ.get"
    assert events[0][1][0] == "TEST_VAR_ENVIRON_GET"


def test_os_environ_subscript_fires_event():
    """Test that os.environ['key'] triggers an os.environ.get audit event."""
    import os

    events = []

    def hook(event, args):
        if event == "os.environ.get":
            events.append((event, args))

    install_hook(hook)
    # Use a key we know exists to avoid KeyError
    _ = os.environ["PATH"]
    uninstall_hook()

    assert len(events) == 1
    assert events[0][0] == "os.environ.get"
    assert events[0][1][0] == "PATH"


def test_os_getenv_no_double_event():
    """Test that os.getenv only fires one event (not also os.environ.get)."""
    import os

    events = []

    def hook(event, args):
        if event in ("os.getenv", "os.environ.get"):
            events.append((event, args))

    install_hook(hook)
    os.getenv("TEST_NO_DOUBLE")
    uninstall_hook()

    # Should only have one event (os.getenv), not two (os.getenv + os.environ.get)
    assert len(events) == 1
    assert events[0][0] == "os.getenv"

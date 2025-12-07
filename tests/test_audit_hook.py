import pytest

from malwi_box import install_hook, uninstall_hook


def test_install_and_capture_exec_event():
    """Test that audit hooks capture exec events."""
    events = []

    def hook(event, args):
        if event == "exec":
            events.append(event)

    install_hook(hook)
    exec("x = 1")
    uninstall_hook()

    assert len(events) == 1
    assert events[0] == "exec"


def test_uninstall_stops_capturing():
    """Test that uninstall_hook stops the callback from being invoked."""
    events = []

    def hook(event, args):
        events.append(event)

    install_hook(hook)
    exec("x = 1")

    uninstall_hook()
    # Count AFTER uninstall completes (some events may fire during uninstall)
    count_after_uninstall = len(events)

    exec("y = 2")
    count_after_exec = len(events)

    # No new events should be captured after uninstall completes
    assert count_after_exec == count_after_uninstall


def test_callback_receives_event_and_args():
    """Test that callback receives correct event type and args tuple."""
    captured = []

    def hook(event, args):
        captured.append((event, args))

    install_hook(hook)
    exec("z = 42")
    uninstall_hook()

    # Find the exec event
    exec_events = [(e, a) for e, a in captured if e == "exec"]
    assert len(exec_events) >= 1

    event, args = exec_events[0]
    assert event == "exec"
    assert isinstance(args, tuple)


def test_callback_must_be_callable():
    """Test that set_callback raises TypeError for non-callable."""
    with pytest.raises(TypeError):
        install_hook("not a callable")


def test_blocklist_skips_events():
    """Test that events in blocklist are not passed to callback."""
    events = []

    def hook(event, args):
        events.append(event)

    # Block 'exec' events
    install_hook(hook, blocklist=["exec"])
    exec("x = 1")
    uninstall_hook()

    # 'exec' should not be in captured events
    assert "exec" not in events


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

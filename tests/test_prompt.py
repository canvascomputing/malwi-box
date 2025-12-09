"""Tests for the _prompt_approval function."""

from unittest.mock import MagicMock, patch

import pytest

from malwi_box.hook import _prompt_approval


def create_mock_tty(read_value: str):
    """Create mock file objects for /dev/tty."""
    mock_tty_in = MagicMock()
    mock_tty_in.__enter__ = MagicMock(return_value=mock_tty_in)
    mock_tty_in.__exit__ = MagicMock(return_value=False)
    mock_tty_in.readline.return_value = read_value

    mock_tty_out = MagicMock()
    mock_tty_out.__enter__ = MagicMock(return_value=mock_tty_out)
    mock_tty_out.__exit__ = MagicMock(return_value=False)

    return mock_tty_in, mock_tty_out


class TestPromptApproval:
    """Tests for _prompt_approval() function."""

    def test_tty_success_yes(self):
        """Test approval via /dev/tty with 'y' response."""
        mock_tty_in, mock_tty_out = create_mock_tty("y\n")

        def open_side_effect(path, mode="r"):
            if mode == "r":
                return mock_tty_in
            return mock_tty_out

        with patch("builtins.open", side_effect=open_side_effect):
            result = _prompt_approval()

        assert result == "y"
        mock_tty_out.write.assert_called_with("Approve? [Y/n/i]: ")
        mock_tty_out.flush.assert_called()

    def test_tty_success_no(self):
        """Test denial via /dev/tty with 'n' response."""
        mock_tty_in, mock_tty_out = create_mock_tty("n\n")

        def open_side_effect(path, mode="r"):
            if mode == "r":
                return mock_tty_in
            return mock_tty_out

        with patch("builtins.open", side_effect=open_side_effect):
            result = _prompt_approval()

        assert result == "n"

    def test_tty_success_inspect(self):
        """Test inspect via /dev/tty with 'i' response."""
        mock_tty_in, mock_tty_out = create_mock_tty("i\n")

        def open_side_effect(path, mode="r"):
            if mode == "r":
                return mock_tty_in
            return mock_tty_out

        with patch("builtins.open", side_effect=open_side_effect):
            result = _prompt_approval()

        assert result == "i"

    def test_tty_strips_whitespace(self):
        """Test that response is stripped of whitespace."""
        mock_tty_in, mock_tty_out = create_mock_tty("  Y  \n")

        def open_side_effect(path, mode="r"):
            if mode == "r":
                return mock_tty_in
            return mock_tty_out

        with patch("builtins.open", side_effect=open_side_effect):
            result = _prompt_approval()

        assert result == "y"  # lowercase and stripped

    def test_fallback_to_input_on_oserror(self):
        """Test fallback to input() when /dev/tty is not available."""
        with patch("builtins.open", side_effect=OSError("No TTY")):
            with patch("builtins.input", return_value="y") as mock_input:
                result = _prompt_approval()

        assert result == "y"
        mock_input.assert_called_once_with("Approve? [Y/n/i]: ")

    def test_fallback_input_strips_and_lowercases(self):
        """Test that fallback input is also stripped and lowercased."""
        with patch("builtins.open", side_effect=OSError("No TTY")):
            with patch("builtins.input", return_value="  N  ") as mock_input:
                result = _prompt_approval()

        assert result == "n"

    def test_empty_response_via_tty(self):
        """Test empty response (just Enter) via /dev/tty."""
        mock_tty_in, mock_tty_out = create_mock_tty("\n")

        def open_side_effect(path, mode="r"):
            if mode == "r":
                return mock_tty_in
            return mock_tty_out

        with patch("builtins.open", side_effect=open_side_effect):
            result = _prompt_approval()

        assert result == ""  # Empty string, which is treated as default (yes)

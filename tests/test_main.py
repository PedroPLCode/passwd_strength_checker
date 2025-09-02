import sys
import os
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import main


def run_main_with_input(mock_password, mock_pwned_return=0, side_effect=None):
    """
    Helper function to run main.main() with mocked dependencies.

    Args:
        mock_password (str or int): Password to be returned by getpass.getpass.
        mock_pwned_return (int): Value returned by PasswordAnalyzer.check_pwned.
        side_effect (Exception, optional): Exception to raise during PasswordAnalyzer.__init__.

    Returns:
        mock_print: Mock object capturing printed output.
    """
    with patch("getpass.getpass", return_value=mock_password), \
         patch("utils.password_analyzer.PasswordAnalyzer.check_pwned", return_value=mock_pwned_return), \
         patch("time.sleep", return_value=None), \
         patch("builtins.print") as mock_print:

        if side_effect:
            with patch("utils.password_analyzer.PasswordAnalyzer.__init__", side_effect=side_effect):
                with pytest.raises(Exception):
                    main.main()
            return mock_print

        main.main()
        return mock_print


def test_valid_password_not_in_breach():
    """Test that a valid password not found in breaches prints the correct message."""
    mock_print = run_main_with_input("StrongPass123!@", mock_pwned_return=0)
    printed = " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
    assert "Password not found in known breaches" in printed


def test_valid_password_in_breach():
    """Test that a password found in breaches prints a warning message with the count."""
    mock_print = run_main_with_input("LeakedPass123!", mock_pwned_return=42)
    printed = " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
    assert "Password found 42 times in breaches" in printed


def test_password_empty(monkeypatch):
    """Test that an empty password input triggers the correct error message."""
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "")
    with patch("builtins.print") as mock_print:
        main.main()
        printed = " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
        assert "Password cannot be empty" in printed


def test_password_not_string(monkeypatch):
    """Test that non-string password input triggers the correct error message."""
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: 12345)
    with patch("builtins.print") as mock_print:
        main.main()
        printed = " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
        assert "Password must be string" in printed


def test_pwned_api_error(monkeypatch):
    """Test handling of HaveIBeenPwned API error (-1 return value)."""
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "SomePass123!")

    with patch("utils.password_analyzer.PasswordAnalyzer.check_pwned", return_value=-1), \
         patch("builtins.print") as mock_print:
        main.main()
        printed = " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
        assert "Could not check password" in printed


def test_keyboard_interrupt(monkeypatch):
    """Test that KeyboardInterrupt raised by the user is handled gracefully."""
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt))
    with patch("builtins.print") as mock_print:
        main.main()
        printed = " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
        assert "Process interrupted by user" in printed


def test_unexpected_exception(monkeypatch):
    """Test that unexpected exceptions during PasswordAnalyzer initialization are caught and printed."""
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "ValidPass123!")
    with patch("utils.password_analyzer.PasswordAnalyzer.__init__", side_effect=RuntimeError("boom")), \
         patch("builtins.print") as mock_print:
        main.main()
        printed = " ".join(" ".join(str(arg) for arg in call.args) for call in mock_print.call_args_list)
        assert "Exception: boom" in printed

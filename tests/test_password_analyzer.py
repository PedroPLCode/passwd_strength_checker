import sys
import os
import pytest
import hashlib
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.password_analyzer import PasswordAnalyzer


def test_evaluate_criteria_various_cases():
    """
    Test that password criteria evaluation works correctly for various passwords.
    Checks both very weak and strong password scenarios.
    """
    analyzer = PasswordAnalyzer("abc")  # weak password
    criteria = analyzer.evaluate_criteria()
    assert criteria["Length >= 8"] is False
    assert criteria["Lowercase letter"] is True
    assert criteria["Uppercase letter"] is False
    assert analyzer.score == sum(criteria.values())

    analyzer = PasswordAnalyzer("Abcd1234!@#&")  # strong password
    criteria = analyzer.evaluate_criteria()
    assert all(criteria.values())  # all criteria should be met
    assert analyzer.score == 6


@pytest.mark.parametrize(
    "password,expected_score",
    [
        ("", 0),
        ("abcdefg", 1),  # only lowercase
        ("abcdefgh", 2),  # length >= 8 + lowercase
        ("Abcdefgh", 3),  # + uppercase
        ("Abcdefg1", 4),  # + digit
        ("Abcdefg1!", 5),  # + special character
        ("Abcdefghij1!", 6),  # all criteria
    ],
)
def test_calculate_score(password, expected_score):
    """
    Test calculation of numeric password strength score for different passwords.
    """
    analyzer = PasswordAnalyzer(password)
    assert analyzer.score == expected_score


@pytest.mark.parametrize(
    "score,expected_level",
    [
        (0, "Very Weak"),
        (1, "Weak"),
        (2, "Medium"),
        (3, "Strong"),
        (4, "Strong"),
        (5, "Very Strong"),
        (6, "Very Strong"),
        (99, "Unknown"),
    ],
)
def test_strength_level(score, expected_level):
    """
    Test conversion of numeric score to descriptive strength level.
    """
    assert PasswordAnalyzer.strength_level(score) == expected_level


def test_check_pwned_password_found(monkeypatch):
    """
    Test the case when the password is found in a known data breach.
    """
    fake_sha1 = hashlib.sha1(b"password").hexdigest().upper()
    prefix, suffix = fake_sha1[:5], fake_sha1[5:]
    mock_response = MagicMock()
    mock_response.text = f"{suffix}:12345\n"
    mock_response.raise_for_status = lambda: None

    with patch(
        "utils.password_analyzer.requests.get", return_value=mock_response
    ) as mock_get:
        count = PasswordAnalyzer.check_pwned("password")
        assert count == 12345
        mock_get.assert_called_once()


def test_check_pwned_password_not_found(monkeypatch):
    """
    Test the case when the password is not found in any known data breach.
    """
    fake_sha1 = hashlib.sha1(b"unique_pass").hexdigest().upper()
    prefix, suffix = fake_sha1[:5], fake_sha1[5:]
    mock_response = MagicMock()
    mock_response.text = f"AAAAAA:10\nBBBBBB:20\n"  # suffix does not match
    mock_response.raise_for_status = lambda: None

    with patch("utils.password_analyzer.requests.get", return_value=mock_response):
        count = PasswordAnalyzer.check_pwned("unique_pass")
        assert count == 0


def test_check_pwned_request_error(monkeypatch):
    """
    Test handling of a network/API error when checking the password.
    The function should return -1 on exception.
    """
    with patch(
        "utils.password_analyzer.requests.get", side_effect=Exception("Network error")
    ):
        count = PasswordAnalyzer.check_pwned("whatever")
        assert count == -1

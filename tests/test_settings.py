import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.password_analyzer import PasswordAnalyzer
from settings import pwned_url, strength_levels


def test_strength_levels_mapping():
    """
    Verify that the `strength_levels` dictionary covers all scores from 0 to 6
    and that each value is a string.
    """
    for i in range(7):
        assert i in strength_levels
        assert isinstance(strength_levels[i], str)


def test_pwned_url_format():
    """
    Ensure that the `pwned_url` is a valid URL string pointing to the
    Have I Been Pwned password API.
    """
    assert isinstance(pwned_url, str)
    assert pwned_url.startswith("https://")
    assert "pwnedpasswords.com" in pwned_url


def test_check_pwned_uses_correct_url():
    """
    Ensure that PasswordAnalyzer.check_pwned constructs the correct API URL
    when querying the Have I Been Pwned API.

    This test mocks `hashlib.sha1` and `requests.get` to avoid real API calls.
    """
    password = "Test123!"
    fake_sha1 = "DUMMYSHA1"
    prefix, suffix = fake_sha1[:5], fake_sha1[5:]

    with patch("hashlib.sha1") as mock_sha1, patch(
        "utils.password_analyzer.requests.get"
    ) as mock_get:

        mock_sha1.return_value.hexdigest.return_value = fake_sha1

        mock_response = MagicMock()
        mock_response.text = f"{suffix}:1\n"
        mock_response.raise_for_status = lambda: None
        mock_get.return_value = mock_response

        PasswordAnalyzer.check_pwned(password)

        called_url = mock_get.call_args[0][0]
        assert called_url.startswith(pwned_url)

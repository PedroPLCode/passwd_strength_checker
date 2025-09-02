import sys
import os
import pytest
from colorama import Fore

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from main import print_dynamic_criteria, print_dynamic_strength_bar


@pytest.mark.parametrize(
    "criteria, expected_symbol, expected_color",
    [
        ({"Length >= 8": True}, "[v]", Fore.GREEN),
        ({"Contains number": False}, "[x]", Fore.RED),
    ],
)
def test_print_dynamic_criteria(capsys, monkeypatch, criteria, expected_symbol, expected_color):
    """
    Test that `print_dynamic_criteria` prints the correct symbols and colors for each criterion.

    Args:
        capsys: pytest fixture to capture printed output.
        monkeypatch: pytest fixture to mock time.sleep for faster tests.
        criteria (dict): Dictionary of criteria to test.
        expected_symbol (str): Expected symbol to indicate pass/fail.
        expected_color (str): Expected color code.
    """
    monkeypatch.setattr("time.sleep", lambda _: None)
    print_dynamic_criteria(criteria)
    captured = capsys.readouterr()

    for key in criteria.keys():
        assert expected_symbol in captured.out
        assert expected_color in captured.out
        assert key in captured.out


@pytest.mark.parametrize(
    "score, expected_color, expected_level",
    [
        (0, Fore.RED, "Very Weak"),
        (2, Fore.RED, "Medium"),
        (3, Fore.YELLOW, "Strong"),
        (5, Fore.GREEN, "Very Strong"),
    ],
)
def test_print_dynamic_strength_bar(capsys, score, expected_color, expected_level):
    """
    Test that `print_dynamic_strength_bar` outputs the correct colored strength bar
    and descriptive level based on the numeric password score.

    Args:
        capsys: pytest fixture to capture printed output.
        score (int): Numeric password strength score (0–6).
        expected_color (str): Expected color code for the bar.
        expected_level (str): Expected descriptive strength level.
    """
    print_dynamic_strength_bar(score)
    captured = capsys.readouterr()

    assert expected_color in captured.out
    assert expected_level in captured.out
    assert "█" in captured.out or "░" in captured.out

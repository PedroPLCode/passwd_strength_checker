import time
from colorama import Fore
from utils.password_analyzer import PasswordAnalyzer


def print_dynamic_criteria(criteria: dict):
    """
    Print each password criterion dynamically with colors.
    - Green [v] for met criteria.
    - Red [x] for unmet criteria.

    Args:
        criteria (dict): Dictionary of password criteria and their boolean status.
    """
    for key, value in criteria.items():
        if value:
            print(Fore.GREEN + f"[v] {key}")
        else:
            print(Fore.RED + f"[x] {key}")
        time.sleep(0.2)


def print_dynamic_strength_bar(score: int):
    """
    Print a colored password strength bar based on numeric score.

    Args:
        score (int): Password strength score (0-6).
    """
    bar_length = 20
    filled = int(bar_length * score / 6)
    empty = bar_length - filled

    if score <= 2:
        color = Fore.RED
    elif score <= 4:
        color = Fore.YELLOW
    else:
        color = Fore.GREEN

    bar = color + "█" * filled + Fore.WHITE + "░" * empty
    level = PasswordAnalyzer.strength_level(score)
    print(f"Password Strength: {bar} {level}")

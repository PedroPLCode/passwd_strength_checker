import re
import hashlib
import requests
import time
from colorama import init, Fore
import getpass
from settings import pwned_url

init(autoreset=True)


def password_criteria(password: str) -> dict:
    """
    Check password against each criterion:
    length >= 8, length >= 12, uppercase, lowercase, digits, special characters
    Returns a dictionary with True/False values.
    """
    return {
        "Length >= 8": len(password) >= 8,
        "Length >= 12": len(password) >= 12,
        "Uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Lowercase letter": bool(re.search(r"[a-z]", password)),
        "Digit": bool(re.search(r"[0-9]", password)),
        "Special character": bool(re.search(r"[^A-Za-z0-9]", password))
    }


def password_strength_score(criteria: dict) -> int:
    """Calculate numeric score based on satisfied criteria."""
    return sum(criteria.values())


def password_strength_level(score: int) -> str:
    """Convert numeric score to descriptive level."""
    levels = {
        0: "Very Weak",
        1: "Weak",
        2: "Medium",
        3: "Strong",
        4: "Strong",
        5: "Very Strong",
        6: "Very Strong"
    }
    return levels.get(score, "Unknown")


def print_dynamic_criteria(criteria: dict):
    """Print each criterion with color based on whether it's met."""
    for key, value in criteria.items():
        if value:
            print(Fore.GREEN + f"[✔] {key}")
        else:
            print(Fore.RED + f"[✖] {key}")
        time.sleep(0.2)


def print_dynamic_strength_bar(score: int):
    """Print a colored strength bar based on score."""
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
    level = password_strength_level(score)
    print(f"Password Strength: {bar} {level}")


def check_pwned(password: str) -> int:
    """Check password against HaveIBeenPwned API."""
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"{pwned_url}{prefix}"
        res = requests.get(url, timeout=5)
        res.raise_for_status()
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except requests.exceptions.RequestException:
        return -1


if __name__ == "__main__":
    try:
        pwd = getpass.getpass(Fore.CYAN + "\nEnter a password to check: ").strip()
        if not pwd:
            raise ValueError("Password cannot be empty.")

        print(Fore.CYAN + "\nAnalyzing password criteria...\n")
        criteria = password_criteria(pwd)
        print_dynamic_criteria(criteria)

        score = password_strength_score(criteria)
        print_dynamic_strength_bar(score)

        print(Fore.CYAN + "\nChecking password against HaveIBeenPwned database...")
        leaks = check_pwned(pwd)
        time.sleep(0.5)
        if leaks == -1:
            print(Fore.YELLOW + "⚠️ Could not check password against HaveIBeenPwned API.\n")
        elif leaks == 0:
            print(Fore.GREEN + "✅ Password not found in known breaches.\n")
        else:
            print(Fore.RED + f"⚠️ Password found {leaks} times in breaches! Change it immediately!\n")

    except ValueError as ve:
        print(Fore.RED + f"⚠️ Input error: {ve}\n")
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "\n⏹️ Process interrupted by user.\n")

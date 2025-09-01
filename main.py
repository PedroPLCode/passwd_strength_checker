import re
import hashlib
import requests

def password_strength(password: str) -> str:
    """
    Evaluate the strength of a given password based on length and character variety.
    
    Args:
        password (str): The password to evaluate.
    
    Returns:
        str: Strength level ("Very Weak", "Weak", "Medium", "Strong", "Very Strong").
    """
    if not isinstance(password, str):
        return "Invalid input"

    score = 0

    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1

    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1

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


def check_pwned(password: str) -> int:
    """
    Check if the given password has appeared in known data breaches
    using the HaveIBeenPwned API (k-anonymity model).

    Args:
        password (str): The password to check.

    Returns:
        int: Number of times the password has appeared in breaches.
             Returns -1 if the API request fails.
    """
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        res = requests.get(url, timeout=5)
        res.raise_for_status()

        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0

    except requests.exceptions.Timeout:
        print("⚠️ Request timed out. Please check your internet connection.")
        return -1
    except requests.exceptions.RequestException as e:
        print(f"⚠️ API request failed: {e}")
        return -1
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")
        return -1


if __name__ == "__main__":
    try:
        pwd = input("Enter a password to check: ").strip()
        if not pwd:
            raise ValueError("Password cannot be empty.")

        strength = password_strength(pwd)
        print(f"Password strength: {strength}")

        leaks = check_pwned(pwd)
        if leaks == -1:
            print("⚠️ Could not check password against HaveIBeenPwned API.")
        elif leaks == 0:
            print("✅ Password not found in known breaches.")
        else:
            print(f"⚠️ Password found {leaks} times in breaches! Change it immediately!")

    except ValueError as ve:
        print(f"⚠️ Input error: {ve}")
    except KeyboardInterrupt:
        print("\n⏹️ Process interrupted by user.")

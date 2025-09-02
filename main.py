import time
import getpass
from colorama import Fore
from utils.password_analyzer import PasswordAnalyzer
from utils.print_utils import print_dynamic_criteria, print_dynamic_strength_bar


def main():
    """
    Main function for the password strength checker CLI tool.
    - Prompts the user for a password.
    - Analyzes password strength based on defined criteria.
    - Prints dynamic criteria and strength bar.
    - Checks if the password has been leaked using HaveIBeenPwned API.
    """
    try:
        password = getpass.getpass(Fore.CYAN + "\nEnter a password to check: ")

        if not password:
            raise ValueError("Password cannot be empty.")

        if not isinstance(password, str):
            raise ValueError("Password must be string.")

        password = password.strip()
        analyzer = PasswordAnalyzer(password)
        print(Fore.CYAN + "\nAnalyzing password criteria...\n")
        criteria = analyzer.evaluate_criteria()
        print_dynamic_criteria(criteria)

        analyzer.calculate_score()
        print_dynamic_strength_bar(analyzer.score)

        print(Fore.CYAN + "\nChecking password against HaveIBeenPwned database...")
        leaks = analyzer.check_pwned(password)
        time.sleep(0.5)
        if leaks == -1:
            print(
                Fore.YELLOW
                + "[?] Could not check password against HaveIBeenPwned API.\n"
            )
        elif leaks == 0:
            print(Fore.GREEN + "[v] Password not found in known breaches.\n")
        else:
            print(
                Fore.RED
                + f"[x] Password found {leaks} times in breaches! Change it immediately!\n"
            )

    except ValueError as ve:
        print(Fore.RED + f"ValueError: {ve}\n")
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "\nProcess interrupted by user.\n")
    except Exception as e:
        print(Fore.RED + f"Exception: {e}\n")


if __name__ == "__main__":
    main()

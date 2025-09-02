# Password Strength Checker
A terminal-based Python tool to **analyze password strength** and **check for known data breaches** using the [HaveIBeenPwned API](https://haveibeenpwned.com/Passwords).  
This project provides a **cybersecurity-inspired terminal interface** with colored outputs and dynamic animations.

## Features
- Check password against **common security criteria**:
  - Minimum length (8 and 12 characters)
  - Uppercase letters
  - Lowercase letters
  - Digits
  - Special characters
- Display a **dynamic strength bar** with color coding.
- Check if a password has appeared in known **data breaches** using the HaveIBeenPwned API.
- Terminal animations for a **hacker-style user experience**.
- Modular code structure:
  - `passwd_analyzer.py` – core password analysis logic
  - `print_utils.py` – functions for colored terminal output
  - `main.py` – CLI entry point

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/passwd_strength_checker.git
cd passwd_strength_checker
```
2. (Optional but recommended) Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```
3. Install requirements:
```bash
pip install -r requirements.txt
```

## Usage
Run the main script:
```bash
python3 main.py
```
Enter the password when prompted.
The tool will dynamically display which criteria the password meets.
The strength bar will visualize the password's strength.
The tool will check if the password has appeared in known breaches and display a warning if necessary.

## Dependencies
- Python 3.10+
- colorama
- requests

## Important!
Familiarize yourself thoroughly with the source code. Understand its operation. Only then will you be able to customize and adjust scripts to your own needs, preferences, and requirements. Only then will you be able to use it correctly and avoid potential issues. Knowledge of the underlying code is essential for making informed decisions and ensuring the successful implementation of the app for your specific use case. Make sure to review all components and dependencies before running the scripts.

Project is under GNU General Public License Version 3, 29 June 2007
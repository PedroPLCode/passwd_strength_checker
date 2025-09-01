import re
import hashlib
import requests
from settings import pwned_url, strength_levels

class PasswordAnalyzer:
    """
    Class to analyze password strength and check for known breaches.
    
    Attributes:
        password (str): The password to analyze.
        criteria (dict): Dictionary of password criteria results.
        score (int): Numeric score representing password strength.
    """
    def __init__(self, password: str):
        """
        Initialize the PasswordAnalyzer with a password.
        
        Args:
            password (str): Password to be analyzed.
        """
        self.password = password
        self.criteria = self.evaluate_criteria()
        self.score = self.calculate_score()
        
    def evaluate_criteria(self) -> dict:
        """
        Evaluate password against common security criteria.
        
        Returns:
            dict: Dictionary of criteria names with True/False indicating if met.
        """
        return {
            "Length >= 8": len(self.password) >= 8,
            "Length >= 12": len(self.password) >= 12,
            "Uppercase letter": bool(re.search(r"[A-Z]", self.password)),
            "Lowercase letter": bool(re.search(r"[a-z]", self.password)),
            "Digit": bool(re.search(r"[0-9]", self.password)),
            "Special character": bool(re.search(r"[^A-Za-z0-9]", self.password))
        }
        
    def calculate_score(self) -> int:
        """
        Calculate total password strength score based on criteria.
        
        Returns:
            int: Total score (0-6) representing password strength.
        """
        return sum(self.criteria.values())
    
    @staticmethod
    def strength_level(score: int) -> str:
        """
        Convert numeric score to descriptive strength level.
        
        Args:
            score (int): Numeric password strength score.
            
        Returns:
            str: Descriptive strength level.
        """
        return strength_levels.get(score, "Unknown")

    @staticmethod
    def check_pwned(password: str) -> int:
        """
        Check if the password has appeared in known data breaches using HaveIBeenPwned API.
        
        Args:
            password (str): Password to check.
            
        Returns:
            int: Number of times the password has appeared in breaches, or -1 on error.
        """
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
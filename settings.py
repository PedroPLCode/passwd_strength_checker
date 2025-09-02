"""
pwned_url: API endpoint for the Have I Been Pwned password range check.
strength_levels: Mapping of numeric password scores (0–6) to descriptive strength levels.
"""

pwned_url = "https://api.pwnedpasswords.com/range/"

strength_levels = {
    0: "Very Weak",
    1: "Weak",
    2: "Medium",
    3: "Strong",
    4: "Strong",
    5: "Very Strong",
    6: "Very Strong",
}

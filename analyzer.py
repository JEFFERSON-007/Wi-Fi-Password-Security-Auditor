import os
import re
import math
import json
from datetime import datetime
from typing import Dict, Any, List, Set, Tuple

class PasswordAnalyzer:
    """
    Evaluates the security and strength of a password for Wi-Fi networks.
    Provides detailed score, entropy, crack time, checklist results, and tips.
    """
    def __init__(self, common_passwords_file: str = "common_passwords.json") -> None:
        self.common_passwords: Set[str] = set()
        
        # Resolve path relative to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base_dir, common_passwords_file)
        
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Lowercase all for case-insensitive matching
                    self.common_passwords = {str(pwd).strip().lower() for pwd in data}
        except Exception as e:
            # Fallback if the file can't be read
            print(f"Warning: Could not load common passwords list from {path}: {e}")

    def _check_keyboard_patterns(self, password: str) -> bool:
        """Checks for keyboard sequence patterns of length 3 or more (e.g. qwe, asd, 123)."""
        pwd_lower = password.lower()
        keyboard_rows = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890-="
        ]
        
        # Check standard sequences
        for row in keyboard_rows:
            # Forwards
            for i in range(len(row) - 2):
                seq = row[i:i+3]
                if seq in pwd_lower:
                    return True
            # Backwards
            rev_row = row[::-1]
            for i in range(len(rev_row) - 2):
                seq = rev_row[i:i+3]
                if seq in pwd_lower:
                    return True
        return False

    def _check_sequential_characters(self, password: str) -> bool:
        """Checks for sequential alphabetical characters of length 3 or more (e.g. abc, xyz)."""
        pwd_lower = password.lower()
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        
        for i in range(len(alphabet) - 2):
            seq = alphabet[i:i+3]
            if seq in pwd_lower:
                return True
            rev_seq = seq[::-1]
            if rev_seq in pwd_lower:
                return True
        return False

    def _check_repeated_words(self, password: str) -> bool:
        """Checks if the password is constructed from repeated words (e.g., 'passwordpassword')."""
        if len(password) < 4:
            return False
        # Find repeats like 'abcabc'
        for length in range(2, len(password) // 2 + 1):
            chunk = password[:length]
            if chunk * (len(password) // length) == password:
                return True
        return False

    def calculate_entropy(self, password: str) -> Tuple[float, int, int]:
        """
        Calculates Shannon entropy, character pool size, and estimated combinations.
        Returns Tuple of (entropy_bits, pool_size, combinations).
        """
        if not password:
            return 0.0, 0, 0
            
        pool_size = 0
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        # Non-alphanumeric ASCII symbols
        has_symbol = bool(re.search(r'[^a-zA-Z0-9\s]', password))
        has_unicode = any(ord(c) > 127 for c in password)
        
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_symbol:
            pool_size += 33
        if has_unicode:
            pool_size += 100
            
        if pool_size == 0:
            # Fallback if none of the above are matched (e.g., spaces only)
            pool_size = len(set(password))
            
        combinations = pool_size ** len(password)
        entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0.0
        return entropy, pool_size, combinations

    def _estimate_crack_time(self, combinations: int) -> Dict[str, str]:
        """
        Estimates crack times under various scenarios:
        1. Online Throttled (100 guesses/sec)
        2. Desktop GPU (10,000,000,000 guesses/sec)
        3. GPU Cluster (100,000,000,000,000 guesses/sec)
        """
        scenarios = {
            "online": 100,
            "offline_gpu": 10_000_000_000,
            "gpu_cluster": 100_000_000_000_000
        }
        
        results = {}
        for name, speed in scenarios.items():
            seconds = combinations / speed if speed > 0 else 0
            results[name] = self._format_seconds(seconds)
            
        return results

    def _format_seconds(self, seconds: float) -> str:
        """Converts seconds into human-readable intervals."""
        if seconds < 1:
            return "Instant"
        
        # Time constants
        minute = 60
        hour = 3600
        day = 86400
        month = 2592000 # 30 days
        year = 31536000 # 365 days
        century = 3153600000 # 100 years
        
        if seconds < minute:
            return f"{math.ceil(seconds)} Seconds"
        elif seconds < hour:
            return f"{math.ceil(seconds / minute)} Minutes"
        elif seconds < day:
            return f"{math.ceil(seconds / hour)} Hours"
        elif seconds < month:
            return f"{math.ceil(seconds / day)} Days"
        elif seconds < year:
            return f"{math.ceil(seconds / month)} Months"
        elif seconds < century:
            return f"{math.ceil(seconds / year)} Years"
        elif seconds < (century * 100):
            return f"{math.ceil(seconds / century)} Centuries"
        else:
            return "Eons (10,000+ Years)"

    def analyze(self, password: str) -> Dict[str, Any]:
        """
        Performs the complete security analysis on the provided password.
        Returns a dictionary of analysis metrics, checklist, score, and tips.
        """
        if not password:
            return {
                "score": 0,
                "rating": "Very Weak",
                "entropy": 0.0,
                "pool_size": 0,
                "combinations": 0,
                "crack_times": {"online": "Instant", "offline_gpu": "Instant", "gpu_cluster": "Instant"},
                "checklist": {
                    "length": False,
                    "uppercase": False,
                    "lowercase": False,
                    "numbers": False,
                    "symbols": False,
                    "entropy": False,
                    "common": False,
                    "keyboard": False,
                    "repeated": False
                },
                "recommendations": ["Enter a password to begin the security audit."]
            }

        # 1. Base details
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9\s]', password))
        has_unicode = any(ord(c) > 127 for c in password)
        has_whitespace = bool(re.search(r'\s', password))
        
        # 2. Entropy and Crack Time
        entropy, pool_size, combinations = self.calculate_entropy(password)
        crack_times = self._estimate_crack_time(combinations)
        
        # 3. Pattern checks
        is_common = password.lower().strip() in self.common_passwords
        has_keyboard = self._check_keyboard_patterns(password)
        has_sequential = self._check_sequential_characters(password)
        
        # Check repeated characters (3 consecutive e.g., aaa)
        has_consecutive_repeats = bool(re.search(r'(.)\1\1', password))
        unique_ratio = len(set(password)) / length
        has_low_diversity = unique_ratio < 0.5
        
        # Check contextual patterns
        has_birth_year = bool(re.search(r'(19\d\d|20[0-2]\d)', password))
        has_phone = bool(re.search(r'\b\d{7,10}\b', password))
        # Simple email regex matching
        has_email = bool(re.search(r'[\w.-]+@[\w.-]+\.\w+', password))
        
        # 4. Scoring logic (out of 100)
        score = 0
        
        # Length additions
        score += min(length * 3.5, 42) # Up to 42 points for length 12
        if length >= 12:
            score += 8  # Length bonus
            
        # Character pool diversity (up to 40 points)
        if has_lower:
            score += 10
        if has_upper:
            score += 10
        if has_digit:
            score += 10
        if has_symbol:
            score += 10
        if has_unicode:
            score += 5
            
        # Deduct penalties
        if length > 0 and (password.isalpha() or password.isdigit()):
            score -= 15 # Homogeneous character set penalty
            
        if has_keyboard:
            score -= 10
        if has_sequential:
            score -= 10
        if has_consecutive_repeats:
            score -= 10
        if has_low_diversity:
            score -= 10
        if has_birth_year:
            score -= 5
        if has_phone:
            score -= 10
        if has_email:
            score -= 15
        if has_whitespace:
            score -= 5

        # Check if password is in common passwords database
        if is_common:
            score = min(score, 10)  # Caps the score to a very low value (Very Weak)
            if score > 5:
                score = 5

        # Normalize score
        score = max(0, min(100, int(score)))
        
        # Determine rating
        if score <= 20:
            rating = "Very Weak"
        elif score <= 40:
            rating = "Weak"
        elif score <= 60:
            rating = "Fair"
        elif score <= 80:
            rating = "Good"
        elif score <= 90:
            rating = "Strong"
        else:
            rating = "Excellent"
            
        # 5. Checklist verification
        checklist = {
            "length": length >= 12,
            "uppercase": has_upper,
            "lowercase": has_lower,
            "numbers": has_digit,
            "symbols": has_symbol,
            "entropy": entropy >= 60.0,
            "common": not is_common,
            "keyboard": not has_keyboard,
            "repeated": not (has_consecutive_repeats or has_low_diversity)
        }
        
        # 6. Generate Recommendations
        recommendations = []
        if length < 12:
            recommendations.append(f"Increase password length to at least 12 characters (currently {length}). Length is the single most critical factor.")
        if not has_upper:
            recommendations.append("Include at least one uppercase letter (A-Z) to increase character pool diversity.")
        if not has_lower:
            recommendations.append("Include at least one lowercase letter (a-z).")
        if not has_digit:
            recommendations.append("Include at least one number (0-9).")
        if not has_symbol:
            recommendations.append("Include at least one special symbol (e.g. !, @, #, $, %, etc.).")
        if is_common:
            recommendations.append("CRITICAL: Change this password immediately. It is in common leaked password databases and easily guessed.")
        if has_keyboard:
            recommendations.append("Avoid sequences corresponding to keyboard layouts (like 'qwerty' or 'asdf').")
        if has_sequential:
            recommendations.append("Avoid sequential alphabetical or numerical sequences (like 'abc' or '123').")
        if has_consecutive_repeats or has_low_diversity:
            recommendations.append("Avoid repeating characters sequentially (like 'aaa') and increase the variety of unique characters.")
        if has_birth_year:
            recommendations.append("Avoid including birth years (e.g., 1990-2026), as attackers target these during credential-stuffing.")
        if has_phone or has_email:
            recommendations.append("Avoid using personal identifiable details like phone numbers or email addresses.")
        if has_whitespace:
            recommendations.append("While spaces can be useful in passphrases, avoid unnecessary leading or trailing spaces.")
            
        # General Wi-Fi Best Practices if it's already strong
        if score >= 80:
            recommendations.append("Your Wi-Fi password strength is solid. Ensure WPA3 encryption is enabled on your router.")
            recommendations.append("Regularly update your router's firmware to patch security vulnerabilities.")
            recommendations.append("Use a secure offline password manager to generate and store router credentials.")
        else:
            recommendations.append("For high security, consider using the 'Passphrase' generator to build long, memorable Wi-Fi keys.")
            
        return {
            "score": score,
            "rating": rating,
            "entropy": round(entropy, 2),
            "pool_size": pool_size,
            "combinations": combinations,
            "crack_times": crack_times,
            "checklist": checklist,
            "recommendations": recommendations[:6]  # Cap to top 6 actionable items
        }

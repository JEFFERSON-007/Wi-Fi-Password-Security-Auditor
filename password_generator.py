import secrets
import string
from typing import List

# Pre-defined list of easy-to-remember words for Passphrase Mode
PASSPHRASE_WORDLIST: List[str] = [
    "amber", "anchor", "apple", "apricot", "arrow", "autumn", "badger", "beacon",
    "breeze", "bridge", "cabin", "cactus", "camel", "canyon", "castle", "coyote",
    "crystal", "desert", "dolphin", "dragon", "eagle", "earth", "echo", "elixir",
    "falcon", "fender", "forest", "fossil", "frost", "galaxy", "garden", "gecko",
    "glacier", "guitar", "harbor", "haven", "hawk", "hearth", "heron", "island",
    "jasper", "jungle", "kestrel", "lagoon", "lantern", "legend", "lizard", "marble",
    "meadow", "meteor", "mirror", "monkey", "morning", "nebula", "nomad", "oasis",
    "ocean", "olive", "orbit", "orchid", "otter", "ozone", "pebble", "phoenix",
    "planet", "puddle", "quartz", "radar", "rainbow", "ravine", "rescue", "river",
    "saddle", "safari", "sailor", "shadow", "shield", "sienna", "silver", "sketch",
    "sonic", "sparrow", "spiral", "spring", "summit", "sunflower", "sunset", "talon",
    "temple", "timber", "topaz", "trail", "tundra", "valley", "velvet", "vessel",
    "volcano", "vortex", "walnut", "willow", "winter", "wizard", "zenith", "zephyr",
    "blaze", "bloom", "bounce", "chase", "climb", "dance", "drift", "dash", "dream",
    "float", "glide", "glow", "hover", "leap", "march", "pulse", "reach", "roam",
    "shine", "soar", "spark", "stride", "travel", "tread", "wander", "watch",
    "ancient", "bright", "brave", "clever", "cosmic", "crisp", "exotic", "frozen",
    "gentle", "golden", "happy", "hidden", "loyal", "misty", "rugged", "silent",
    "smooth", "stormy", "swift", "velvet", "vibrant", "warm", "wild", "youthful"
]

class PasswordGenerator:
    """
    Generates cryptographically secure passwords or passphrases.
    Uses Python's standard `secrets` library (PEP 506).
    """
    def __init__(self) -> None:
        self.rng = secrets.SystemRandom()

    def generate_secure_password(
        self,
        length: int = 16,
        use_upper: bool = True,
        use_lower: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = False
    ) -> str:
        """
        Generates a secure password of a given length with specified options.
        Ensures at least one character from each selected set is included.
        """
        # Constrain length
        length = max(8, min(64, length))
        
        # Define character sets
        upper_chars = string.ascii_uppercase
        lower_chars = string.ascii_lowercase
        digit_chars = string.digits
        # Router-safe printable special symbols (omitting backtick, double-quote, spaces)
        symbol_chars = "!@#$%^&*()_+-=[]{}|;:',./<>?"
        
        # Exclude ambiguous characters (i, l, 1, o, O, 0, I, |, L) if requested
        if exclude_ambiguous:
            ambiguous = "il1oO0I|L"
            upper_chars = "".join(c for c in upper_chars if c not in ambiguous)
            lower_chars = "".join(c for c in lower_chars if c not in ambiguous)
            digit_chars = "".join(c for c in digit_chars if c not in ambiguous)
            symbol_chars = "".join(c for c in symbol_chars if c not in ambiguous)

        # Build active character pools
        pools = []
        if use_upper and upper_chars:
            pools.append(upper_chars)
        if use_lower and lower_chars:
            pools.append(lower_chars)
        if use_digits and digit_chars:
            pools.append(digit_chars)
        if use_symbols and symbol_chars:
            pools.append(symbol_chars)

        # If no pools selected, default to lower + digits
        if not pools:
            pools = [lower_chars, digit_chars]

        # Combine all characters
        combined_chars = "".join(pools)
        
        # Guarantee at least one character from each active pool to ensure diversity
        password_chars = []
        for pool in pools:
            password_chars.append(self.rng.choice(pool))
            
        # Fill the rest of the password
        remaining_len = length - len(password_chars)
        for _ in range(remaining_len):
            password_chars.append(self.rng.choice(combined_chars))
            
        # Shuffle to mix guaranteed characters
        self.rng.shuffle(password_chars)
        
        return "".join(password_chars)

    def generate_passphrase(
        self,
        words_count: int = 4,
        separator: str = "-",
        capitalize: bool = True
    ) -> str:
        """
        Generates a secure, easily rememberable passphrase using words.
        """
        # Constrain words count between 3 and 10
        words_count = max(3, min(10, words_count))
        
        chosen_words = []
        for _ in range(words_count):
            word = self.rng.choice(PASSPHRASE_WORDLIST)
            if capitalize:
                word = word.capitalize()
            else:
                word = word.lower()
            chosen_words.append(word)
            
        return separator.join(chosen_words)

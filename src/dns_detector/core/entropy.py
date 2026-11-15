import math
from collections import Counter
from typing import Dict, Tuple


def calculate_entropy(text: str) -> float:
    """
    Computes Shannon Entropy (H) in bits per character.
    Formula: H(X) = - sum(P(x_i) * log2(P(x_i)))
    
    Higher entropy indicates greater randomness, typical in Base32/Base64/Hex
    encoded data payloads used in DNS tunneling.
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def calculate_metric_entropy(text: str) -> float:
    """
    Computes Metric Entropy (normalized Shannon entropy divided by string length).
    Useful for distinguishing short random tokens from long exfiltrated payloads.
    """
    if not text:
        return 0.0
    return calculate_entropy(text) / len(text)


def analyze_character_distribution(text: str) -> Dict[str, float]:
    """
    Analyzes lexical characteristics of the domain/subdomain string.
    Returns ratios for hex, digits, vowels, consonants, and unique characters.
    """
    if not text:
        return {
            "length": 0,
            "unique_chars": 0,
            "unique_ratio": 0.0,
            "digit_ratio": 0.0,
            "hex_ratio": 0.0,
            "vowel_ratio": 0.0,
            "consonant_ratio": 0.0,
            "vowel_consonant_ratio": 0.0,
            "max_consecutive_consonants": 0,
        }

    clean_text = text.lower()
    total_len = len(clean_text)
    unique_count = len(set(clean_text))

    hex_chars = set("0123456789abcdef")
    vowels = set("aeiou")
    consonants = set("bcdfghjklmnpqrstvwxyz")

    digits_count = sum(1 for c in clean_text if c.isdigit())
    hex_count = sum(1 for c in clean_text if c in hex_chars)
    vowels_count = sum(1 for c in clean_text if c in vowels)
    consonants_count = sum(1 for c in clean_text if c in consonants)

    # Calculate max consecutive consonants (common sign of hex/base32 or non-natural strings)
    max_consecutive_c = 0
    current_consecutive_c = 0
    for c in clean_text:
        if c in consonants:
            current_consecutive_c += 1
            if current_consecutive_c > max_consecutive_c:
                max_consecutive_c = current_consecutive_c
        else:
            current_consecutive_c = 0

    vc_ratio = (
        vowels_count / consonants_count if consonants_count > 0 else float(vowels_count)
    )

    return {
        "length": total_len,
        "unique_chars": unique_count,
        "unique_ratio": unique_count / total_len,
        "digit_ratio": digits_count / total_len,
        "hex_ratio": hex_count / total_len,
        "vowel_ratio": vowels_count / total_len,
        "consonant_ratio": consonants_count / total_len,
        "vowel_consonant_ratio": vc_ratio,
        "max_consecutive_consonants": max_consecutive_c,
    }

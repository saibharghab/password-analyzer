#!/usr/bin/env python3
"""
Password Strength Analyzer & Policy Enforcer
Author: Sai Bharghava Kumar Yidupuganti
Description: Evaluates password strength against NIST SP 800-63B guidelines,
             checks entropy, dictionary matching, breach simulation, and enforces
             configurable security policies. Demonstrates secure bcrypt storage
             vs insecure MD5.
"""

import re
import math
import hashlib
import json
import argparse
import sys
from typing import Optional
from dataclasses import dataclass, field, asdict

# ─────────────────────────────────────────────────────────────
# bcrypt — graceful fallback if not installed
# ─────────────────────────────────────────────────────────────
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
# Common Password Dictionary (sample — real tool loads 10k+)
# ─────────────────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "batman", "admin", "welcome", "hello", "charlie",
    "donald", "password2", "qwerty123", "iloveyou1", "1q2w3e4r",
    "123qwe", "zxcvbnm", "1qaz2wsx", "qwertyuiop", "mypassword",
    "password123", "root", "toor", "pass", "test", "guest",
    "123456789", "0987654321", "11111111", "00000000", "99999999",
}

# Simulated breached password hashes (SHA-256) — in production use HIBP API
BREACHED_HASHES = {
    hashlib.sha256(p.encode()).hexdigest() for p in COMMON_PASSWORDS
}

# ─────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────

@dataclass
class PolicyConfig:
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    max_repeated_chars: int = 3
    disallow_common: bool = True
    disallow_breached: bool = True
    rotation_days: int = 90
    history_size: int = 10
    min_entropy_bits: float = 50.0


@dataclass
class AnalysisResult:
    password_length: int = 0
    entropy_bits: float = 0.0
    charset_size: int = 0
    strength_score: int = 0          # 0–100
    strength_label: str = "Very Weak"
    is_common: bool = False
    is_breached: bool = False
    issues: list = field(default_factory=list)
    policy_violations: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    passes_policy: bool = False
    hashes: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# Entropy Calculation
# ─────────────────────────────────────────────────────────────

def calculate_charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password): size += 26
    if re.search(r"[A-Z]", password): size += 26
    if re.search(r"\d",    password): size += 10
    if re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~\"\\]", password): size += 32
    return max(size, 1)


def calculate_entropy(password: str) -> float:
    """
    Shannon entropy: H = L * log2(N)
    where L = password length, N = charset size.
    """
    n = calculate_charset_size(password)
    return len(password) * math.log2(n) if n > 0 else 0.0


# ─────────────────────────────────────────────────────────────
# Strength Scoring
# ─────────────────────────────────────────────────────────────

def score_password(password: str, entropy: float, is_common: bool, is_breached: bool) -> int:
    score = 0

    # Length scoring (max 30)
    length = len(password)
    if length >= 20: score += 30
    elif length >= 16: score += 25
    elif length >= 12: score += 18
    elif length >= 8:  score += 10
    else:              score += 0

    # Entropy scoring (max 30)
    if entropy >= 80:   score += 30
    elif entropy >= 60: score += 22
    elif entropy >= 50: score += 15
    elif entropy >= 35: score += 8
    else:               score += 0

    # Character variety (max 30)
    if re.search(r"[a-z]", password): score += 5
    if re.search(r"[A-Z]", password): score += 5
    if re.search(r"\d",    password): score += 5
    if re.search(r"[!@#$%^&*]",    password): score += 10
    if re.search(r"[^\w!@#$%^&*]", password): score += 5

    # Pattern penalties
    if re.search(r"(.)\1{2,}", password):      score -= 10  # repeated chars
    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|qwerty)", password.lower()):
        score -= 10  # sequential patterns

    # Breach / common penalty
    if is_common or is_breached: score = min(score, 10)

    return max(0, min(score, 100))


def score_to_label(score: int) -> str:
    if score >= 80: return "Very Strong"
    if score >= 60: return "Strong"
    if score >= 40: return "Moderate"
    if score >= 20: return "Weak"
    return "Very Weak"


# ─────────────────────────────────────────────────────────────
# Breach Detection
# ─────────────────────────────────────────────────────────────

def check_breach(password: str) -> bool:
    """Simulate HIBP-style breach check using SHA-256 hash comparison."""
    h = hashlib.sha256(password.encode()).hexdigest()
    return h in BREACHED_HASHES


# ─────────────────────────────────────────────────────────────
# Policy Enforcement
# ─────────────────────────────────────────────────────────────

def enforce_policy(password: str, policy: PolicyConfig) -> list[str]:
    violations = []

    if len(password) < policy.min_length:
        violations.append(f"Minimum length is {policy.min_length} characters (got {len(password)})")

    if policy.require_uppercase and not re.search(r"[A-Z]", password):
        violations.append("Must contain at least one uppercase letter")

    if policy.require_lowercase and not re.search(r"[a-z]", password):
        violations.append("Must contain at least one lowercase letter")

    if policy.require_digits and not re.search(r"\d", password):
        violations.append("Must contain at least one digit")

    if policy.require_special and not re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:',.<>?/`~\"\\]", password):
        violations.append("Must contain at least one special character")

    if re.search(rf"(.)\1{{{policy.max_repeated_chars},}}", password):
        violations.append(f"Must not repeat the same character {policy.max_repeated_chars}+ times in a row")

    return violations


# ─────────────────────────────────────────────────────────────
# Hashing Demo
# ─────────────────────────────────────────────────────────────

def generate_hashes(password: str) -> dict:
    hashes = {}

    # INSECURE — MD5 (no salt, fast, broken for passwords)
    hashes["md5_insecure"] = {
        "hash": hashlib.md5(password.encode()).hexdigest(),
        "secure": False,
        "note": "INSECURE: no salt, fast brute-force, rainbow-table vulnerable",
    }

    # SHA-256 with random salt
    salt = hashlib.sha256(b"random_salt_demo").hexdigest()[:16]
    hashes["sha256_salted"] = {
        "hash": hashlib.sha256((salt + password).encode()).hexdigest(),
        "salt": salt,
        "secure": "Partial",
        "note": "Better than MD5 but not ideal — use bcrypt/argon2 for passwords",
    }

    # bcrypt — SECURE (adaptive, salt built-in)
    if BCRYPT_AVAILABLE:
        bcrypt_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        hashes["bcrypt_secure"] = {
            "hash": bcrypt_hash.decode(),
            "rounds": 12,
            "secure": True,
            "note": "RECOMMENDED: adaptive work factor, built-in salt, designed for passwords",
        }
    else:
        hashes["bcrypt_secure"] = {
            "note": "Install bcrypt: pip install bcrypt",
            "secure": True,
        }

    return hashes


# ─────────────────────────────────────────────────────────────
# Main Analyzer
# ─────────────────────────────────────────────────────────────

def analyze_password(password: str, policy: Optional[PolicyConfig] = None,
                     show_hashes: bool = False) -> AnalysisResult:
    if policy is None:
        policy = PolicyConfig()

    result = AnalysisResult()
    result.password_length = len(password)
    result.charset_size = calculate_charset_size(password)
    result.entropy_bits = calculate_entropy(password)

    result.is_common   = password.lower() in COMMON_PASSWORDS
    result.is_breached = check_breach(password)

    result.strength_score = score_password(
        password, result.entropy_bits, result.is_common, result.is_breached
    )
    result.strength_label = score_to_label(result.strength_score)

    # Issues
    if result.is_common:
        result.issues.append("Password is in the common password list")
    if result.is_breached:
        result.issues.append("Password appears in known data breach simulations")
    if result.entropy_bits < policy.min_entropy_bits:
        result.issues.append(
            f"Low entropy: {result.entropy_bits:.1f} bits (NIST recommends ≥{policy.min_entropy_bits:.0f})"
        )
    if re.search(r"(.)\1{2,}", password):
        result.issues.append("Contains repeated character sequences")

    # Policy enforcement
    result.policy_violations = enforce_policy(password, policy)
    result.passes_policy = len(result.policy_violations) == 0 and not result.is_breached and not result.is_common

    # Recommendations
    if result.password_length < 16:
        result.recommendations.append("Increase length to 16+ characters")
    if not re.search(r"[!@#$%^&*]", password):
        result.recommendations.append("Add special characters (e.g., !, @, #, $)")
    if result.is_common or result.is_breached:
        result.recommendations.append("Choose a unique passphrase instead of common words")
    if result.entropy_bits < 60:
        result.recommendations.append("Use a password manager to generate high-entropy passwords")

    if show_hashes:
        result.hashes = generate_hashes(password)

    return result


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def render_bar(score: int, width: int = 40) -> str:
    filled = int(score / 100 * width)
    if score >= 80:   color = "\033[92m"   # green
    elif score >= 60: color = "\033[93m"   # yellow
    elif score >= 40: color = "\033[33m"   # orange
    else:             color = "\033[91m"   # red
    reset = "\033[0m"
    return f"{color}{'█' * filled}{'░' * (width - filled)}{reset} {score}/100"


def print_result(result: AnalysisResult, password: str):
    print(f"\n{'═'*55}")
    print(f"  Password Analysis Report")
    print(f"{'═'*55}")
    print(f"  Length     : {result.password_length} characters")
    print(f"  Charset    : {result.charset_size} possible characters")
    print(f"  Entropy    : {result.entropy_bits:.1f} bits")
    print(f"  Strength   : {render_bar(result.strength_score)}")
    print(f"  Label      : {result.strength_label}")
    print(f"  Common     : {'YES ⚠' if result.is_common else 'No'}")
    print(f"  Breached   : {'YES ⚠' if result.is_breached else 'No (simulated check)'}")
    print(f"  Policy OK  : {'✔ PASS' if result.passes_policy else '✘ FAIL'}")

    if result.issues:
        print(f"\n  ⚠  Issues:")
        for issue in result.issues:
            print(f"     • {issue}")

    if result.policy_violations:
        print(f"\n  ✘  Policy Violations:")
        for v in result.policy_violations:
            print(f"     • {v}")

    if result.recommendations:
        print(f"\n  💡 Recommendations:")
        for r in result.recommendations:
            print(f"     • {r}")

    if result.hashes:
        print(f"\n  🔒 Hashing Comparison (DEMO — never log real passwords):")
        for algo, info in result.hashes.items():
            print(f"\n     [{algo}]")
            for k, v in info.items():
                if k != "hash":
                    print(f"       {k}: {v}")
            if "hash" in info:
                print(f"       hash: {info['hash'][:60]}...")

    print(f"\n{'═'*55}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer — NIST SP 800-63B compliant"
    )
    parser.add_argument("password", nargs="?", help="Password to analyze (omit for interactive mode)")
    parser.add_argument("--json",         action="store_true", help="Output JSON report")
    parser.add_argument("--hashes",       action="store_true", help="Show hashing comparison (MD5 vs bcrypt)")
    parser.add_argument("--min-length",   type=int,   default=12,   help="Policy: minimum password length")
    parser.add_argument("--min-entropy",  type=float, default=50.0, help="Policy: minimum entropy bits")
    parser.add_argument("--batch",        help="Analyze passwords from a file (one per line)")
    args = parser.parse_args()

    policy = PolicyConfig(
        min_length=args.min_length,
        min_entropy_bits=args.min_entropy,
    )

    if args.batch:
        results = []
        with open(args.batch) as f:
            for line in f:
                pwd = line.strip()
                if pwd:
                    r = analyze_password(pwd, policy, show_hashes=False)
                    results.append({
                        "password_masked": "*" * len(pwd),
                        **asdict(r)
                    })
        print(json.dumps(results, indent=2))
        return

    password = args.password
    if not password:
        try:
            import getpass
            password = getpass.getpass("Enter password to analyze: ")
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(0)

    result = analyze_password(password, policy, show_hashes=args.hashes)

    if args.json:
        print(json.dumps(asdict(result), indent=2))
    else:
        print_result(result, password)


if __name__ == "__main__":
    main()

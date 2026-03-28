# Password Strength Analyzer & Policy Enforcer

A Python tool that evaluates password strength against **NIST SP 800-63B** guidelines, performs entropy scoring, common-password dictionary matching, breach detection simulation, and enforces configurable security policies. Also demonstrates why **bcrypt** is secure vs **MD5** insecure for password storage.

---

## Features

- **Entropy scoring** — Shannon entropy calculation with charset detection
- **Dictionary matching** — 10,000+ common passwords (sample: 50 entries in repo)
- **Breach detection simulation** — SHA-256 hash comparison against known-bad passwords (production: integrates with HIBP API)
- **Policy enforcement** — configurable minimum length, complexity rules, character requirements, and repeat-character limits (NIST SP 800-63B compliant)
- **Hashing comparison** — bcrypt (secure, adaptive) vs SHA-256 with salt vs MD5 (insecure)
- **Batch mode** — analyze a file of passwords and output JSON report
- **Visual strength bar** in terminal output

---

## NIST SP 800-63B Alignment

| NIST Guideline | Implemented |
|---|---|
| Minimum 8 chars (we default to 12) | ✔ |
| Check against breached password lists | ✔ |
| Allow all printable ASCII characters | ✔ |
| No mandatory complexity rules (NIST actually discourages forced rotation) | Configurable |
| No password hints | ✔ (never stored) |

---

## Installation

```bash
git clone https://github.com/saibharghab/password-analyzer
cd password-analyzer

# Optional: install bcrypt for secure hashing demo
pip install bcrypt
```

---

## Usage

```bash
# Interactive mode (password hidden from terminal)
python analyzer.py

# Analyze a specific password
python analyzer.py "MyP@ssw0rd123"

# Show hashing comparison (MD5 vs bcrypt demo)
python analyzer.py "MyP@ssw0rd123" --hashes

# JSON output
python analyzer.py "MyP@ssw0rd123" --json

# Custom policy
python analyzer.py "MyP@ssw0rd123" --min-length 16 --min-entropy 60

# Batch analysis
python analyzer.py --batch passwords.txt --json
```

---

## Example Output

```
═══════════════════════════════════════════════════════
  Password Analysis Report
═══════════════════════════════════════════════════════
  Length     : 13 characters
  Charset    : 94 possible characters
  Entropy    : 85.2 bits
  Strength   : ████████████████████████████████████░░░░ 76/100
  Label      : Strong
  Common     : No
  Breached   : No (simulated check)
  Policy OK  : ✔ PASS

  💡 Recommendations:
     • Use a password manager to generate high-entropy passwords
═══════════════════════════════════════════════════════
```

---

## Hashing Comparison Demo

```
  🔒 Hashing Comparison (DEMO — never log real passwords):

     [md5_insecure]
       secure: False
       note: INSECURE: no salt, fast brute-force, rainbow-table vulnerable

     [sha256_salted]
       secure: Partial
       note: Better than MD5 but not ideal — use bcrypt/argon2 for passwords

     [bcrypt_secure]
       rounds: 12
       secure: True
       note: RECOMMENDED: adaptive work factor, built-in salt, designed for passwords
```

---

## Tech Stack

- Python 3.10+
- `hashlib` — SHA-256, MD5 hashing
- `bcrypt` — secure password hashing (optional)
- `re`, `math` — pattern analysis and entropy calculation
- `argparse` — CLI interface
- `dataclasses` — structured result objects

---

## Author

**Sai Bharghava Kumar Yidupuganti**  
M.S. Information Technology (Network Engineering) — Northern Arizona University  
[LinkedIn](https://linkedin.com/in/yidupuganti-sai-bharghava-kumar-b41388221) | [GitHub](https://github.com/saibharghab)

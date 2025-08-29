# cybertoolv1

# 🔑 JWT IDOR Fuzzer

`jwt_fuzzer` is a Python-based fuzzing tool for **JSON Web Tokens (JWTs)**.
It helps penetration testers and security researchers detect **Insecure Direct Object References (IDOR)**, weak signature validation, and privilege escalation vulnerabilities by generating fuzzed JWT variations.

---

## ✨ Features

* 🔍 **Analyze JWTs**: Decode and identify potential IDOR-related fields.
* 🎲 **Fuzz Payloads**:

  * Randomized values (emails, UUIDs, usernames).
  * Sequential IDs for SIDs and UUID-like fields.
  * Privilege escalation attempts (`role`, `admin`, `is_admin`, etc.).
* 🔓 **Weak Secret Testing**: Generates tokens signed with common weak secrets (`secret`, `123456`, etc.).
* ❌ **Unsigned JWTs**: Creates tokens with `alg: none` for bypass testing.
* 📂 **Burp Suite Integration**: Export fuzzed tokens for Intruder.

---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/jwt_fuzzer.git
cd jwt_fuzzer
pip install pyjwt
```

Requires **Python 3.7+**.

---

## 🚀 Usage

### Basic Analysis

```bash
python3 jwt_fuzzer.py <jwt_token> --analyze-only
```

* Decodes the token.
* Prints header, payload, and possible IDOR fields.

### Generate Fuzzed Tokens

```bash
python3 jwt_fuzzer.py <jwt_token> -c 30 -o fuzzed_tokens.txt
```

* `-c` → Number of tokens to generate (default: 20).
* `-o` → Output file (default: `jwt_payloads.txt`).

### Example

```bash
python3 jwt_fuzzer.py eyJhbGciOi...your.jwt.token... -c 25
```

---

## 📤 Burp Suite Intruder Integration

The tool outputs fuzzed tokens into `jwt_payloads.txt`.
Use them in Burp Suite Intruder as follows:

1. Add a request with an `Authorization` header.
2. Set payload position:

   ```
   Authorization: Bearer §jwt_token§
   ```
3. Load `jwt_payloads.txt` into Intruder’s payload set.
4. Launch attack to test endpoints with fuzzed tokens.

---

## 🧪 Example Output

```text
=== Original JWT Analysis ===
Header: {
  "alg": "HS256",
  "typ": "JWT"
}
Payload: {
  "unique_name": "Felcon September",
  "email": "felconsec@wearehackerone.com",
  "sid": "00000000-0000-0000-0342-ab857e74c03a"
}

=== Potential IDOR Fields ===
- unique_name: Felcon September
- email: felconsec@wearehackerone.com
- sid: 00000000-0000-0000-0342-ab857e74c03a

Exported 20 tokens to jwt_payloads.txt
Use the tokens in Burp Suite Intruder.
```

---

## ⚠️ Disclaimer

This tool is intended **for educational and authorized security testing only**.
Do not use it against systems without **explicit permission**. Unauthorized use may violate laws.

---

## 📜 License

MIT License – Free to use and modify.

---



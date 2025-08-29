# README

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

## 📂 Example `jwt_payloads.txt`

When you run the tool, you’ll get a file like this (example with 5 tokens):

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1bmlxdWVfbmFtZSI6IlVzZXIzNTI4Iiwic3ViIjoiZDQ4ZjAzNjAtYjE4Mi00ZjQ5LTgxZjctYzM1ZWFmNzY4YzJmIiwiaWF0IjoxNzUwODcxOTU0LCJuYmYiOjE3NTA4NzE5NTQsImV4cCI6MTc1MDg3NTU1NH0.
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InJ3Z2VlaWVAZ21haWwuY29tIiwidXNlcl9pZCI6IjM2YjZlZGI0LWQ2N2ItNGIxNS05ZmZkLTlhYjY5MmVjMmU2NyIsImlhdCI6MTc1MDg3MTk1NCwibmJmIjoxNzUwODcxOTU0LCJleHAiOjE3NTA4NzU1NTR9.M3pGJ8ZYYq3Qnl5pgn-M8r8eqhU
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IlVzZXIxMjM0Iiwic2lkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAxIiwiaWF0IjoxNzUwODcxOTU0LCJuYmYiOjE3NTA4NzE5NTQsImV4cCI6MTc1MDg3NTU1NH0.LfK2vQvNITkxM0Hx5
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NTA4NzE5NTQsIm5iZiI6MTc1MDg3MTk1NCwiZXhwIjoxNzUwODc1NTU0fQ.1A-wkUl7y0j69eRW
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc19hZG1pbiI6dHJ1ZSwiaWF0IjoxNzUwODcxOTU0LCJuYmYiOjE3NTA4NzE5NTQsImV4cCI6MTc1MDg3NTU1NH0.iAH5O9uC2Qw9TyN0
```

### 🔎 What’s inside

1. **Unsigned JWT** (`alg: none`) with fuzzed `unique_name` + `sub` (UUID).
2. **HS256 with weak secret** (`secret`) and fuzzed email + user\_id.
3. **Sequential SID variation** (`...0001`).
4. **Privilege escalation attempt** (`role: admin`).
5. **Privilege escalation attempt** (`is_admin: true`).

---

## ⚠️ Disclaimer

This tool is intended **for educational and authorized security testing only**.
Do not use it against systems without **explicit permission**. Unauthorized use may violate laws.

---

## 📜 License

MIT License – Free to use and modify.

---


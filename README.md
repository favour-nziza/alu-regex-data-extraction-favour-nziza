# Regex Onboarding Hackathon — Data Extraction & Secure Validation

**Author:** Favour Nziza
**GitHub:** favour-nziza

## Overview

This program simulates a small piece of a real support/ops pipeline: it
takes raw, messy text (the kind an external API or log export would return)
and pulls structured data out of it — while treating the input as
untrusted, not as something safe to parse blindly.

It extracts:
- **Emails**, classified into ALU official (`@alueducation.com`), ALU
  alumni (`@alumni.alueducation.com`), ALU SI (`@si.alueducation.com`),
  and general emails.
- **Phone numbers** in several real-world formats (international,
  parenthesized area code, dotted, dashed, with extensions).
- **Credit card numbers**, which are validated with the **Luhn
  algorithm** and **masked** everywhere except the last 4 digits.
- **URLs** (flagging whether each one is HTTPS or not).
- **IPv4 addresses**, with real octet-range validation (`0–255` per
  octet) so malformed addresses like `999.999.999.999` are correctly
  rejected instead of being naively matched.
- **Dates** (`YYYY-MM-DD` and `MM/DD/YYYY`), checked against the
  calendar (`datetime.strptime`) so an impossible date like `02/30/2026`
  would be rejected even if it "looks" like a date to a regex.

## Security handling

Every line of input is screened **before** any extraction happens. A line
that trips one of these checks is not "cleaned up and processed anyway" —
it's excluded from extraction entirely and logged separately with the
reason:

| Check | Looks for |
|---|---|
| `sql_injection` | `' OR '1'='1'`-style tautologies, `DROP/DELETE/INSERT/UPDATE ... TABLE/FROM/INTO`, SQL comment markers (`'--`, `;--`) |
| `script_injection` | `<script>` tags, `javascript:` URIs, inline event handlers (`onerror=`, etc.) |
| `path_traversal` | Repeated `../` or `..\` sequences |
| `null_byte_or_encoded_control` | Literal or encoded null bytes (`%00`, `\x00`) |
| `overflow_probe` | A single character repeated 40+ times in a row (classic fuzzing/buffer-overflow probe signature) |

Additionally:
- Credit card numbers are **never printed or stored in full** — only a
  masked value (`************6467`) plus a `luhn_valid` boolean ever
  appear in the output or console.
- The rejected-line report stores only a short 60-character preview, not
  the full raw payload, so the security report itself can't be replayed
  as an attack.
- Extraction uses **span-based precedence** (emails → URLs → IPs → credit
  cards → dates → phone numbers): once a piece of text is claimed by a
  more specific pattern, looser patterns (like the phone-number matcher)
  are not allowed to also match it. This is what stops a 16-digit credit
  card or a dotted-quad IP address from being double-counted as a phone
  number.

## File structure

```
alu-regex-data-extraction-favour-nziza/
├── input/
│   └── raw-text.txt        # realistic, messy sample input (support-ticket export)
├── src/
│   └── main.py              # all extraction, validation, and security logic
├── output/
│   └── sample-output.json   # generated results from running main.py on raw-text.txt
└── README.md
```

## How to run it

Requires only Python 3 (standard library — no external dependencies).

```bash
cd src
python3 main.py                                   # uses the default paths below
# equivalent to:
python3 main.py ../input/raw-text.txt ../output/sample-output.json

# or point it at any other file:
python3 main.py /path/to/your-input.txt /path/to/your-output.json
```

The program prints a summary to the console (totals + which lines were
rejected and why) and writes the full structured results as JSON to the
output path.

## Sample input design

`input/raw-text.txt` is written as a mock support-ticket export and
deliberately includes:
- Real, valid-looking data in several formats and inconsistent spacing.
- ALU-specific email domains (official / alumni / SI) mixed with a
  personal, non-ALU email.
- Two valid (Luhn-passing) card numbers and one that fails Luhn on
  purpose, plus one **incomplete** card number that shouldn't validate
  as a card at all.
- A deliberately invalid IPv4 address (`999.999.999.999`).
- A dedicated "flagged by WAF" ticket block containing a SQL injection
  attempt, an XSS payload, a path-traversal attempt, and a null-byte /
  overflow-style payload — to demonstrate the security screening.

## Known limitations

- Phone number matching is format-based (regex can't verify a number is
  actually dialable) — it's tuned to the formats shown in the sample
  input plus common variants, not to every phone format worldwide.
- Email pattern validates structure/domain, not deliverability (it can't
  know if a mailbox actually exists).
- This is a validation and extraction exercise, not a full security
  system — it is meant to demonstrate defensive thinking, not to replace
  a real WAF, input sanitizer, or PCI-compliant card handling.

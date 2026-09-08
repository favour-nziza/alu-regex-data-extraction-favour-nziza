#!/usr/bin/env python3
"""
Regex Onboarding Hackathon - Data Extraction & Secure Validation
Author: Favour Nziza

WHAT THIS PROGRAM DOES
-----------------------
Reads a raw text file (simulating messy production data returned by an
external API / log dump) and:
  1. Extracts structured data: emails (with ALU-specific classification),
     phone numbers, credit card numbers, URLs, IPv4 addresses, and dates.
  2. Validates what it extracts (proper email domains, Luhn-checked cards,
     real IPv4 octet ranges) instead of blindly trusting regex matches.
  3. Screens every line for signs of hostile/malformed input (SQL
     injection, script/XSS payloads, path traversal, null-byte / overflow
     style junk) BEFORE running extraction on it, and reports what it
     rejected instead of silently processing it as normal text.
  4. Handles sensitive data responsibly: credit card numbers are masked
     everywhere in the output/logs except a proof-of-match last 4 digits.

Run:
    python3 main.py ../input/raw-text.txt ../output/sample-output.json

If no arguments are given it defaults to those two paths (see bottom of
file), so it also works when run from inside src/.
"""

import re
import sys
import json
import os
from datetime import datetime


# ---------------------------------------------------------------------------
# SECTION 1: SECURITY - hostile / malformed input screening
# ---------------------------------------------------------------------------
# These patterns look for content that is trying to manipulate application
# logic or downstream systems rather than describe real data. We check every
# line against this list FIRST. A line that trips one of these is treated as
# unsafe and is excluded from normal extraction entirely - we do not try to
# "clean it up" and still extract from it, because a payload can be crafted
# to look partially like real data on purpose.
SUSPICIOUS_PATTERNS = {
    "sql_injection": re.compile(
        r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)"   # ' OR '1'='1
        r"|(\b(DROP|DELETE|INSERT|UPDATE)\s+(TABLE|FROM|INTO)\b)"
        r"|(['\";]\s*--)",  # SQL comment marker, only after a quote/semicolon
        # (a bare "--" is common in plain-text section dividers like
        # "--- Ticket #123 ---" and is NOT on its own a sign of injection)
        re.IGNORECASE,
    ),
    "script_injection": re.compile(
        r"<\s*script\b|javascript\s*:|on\w+\s*=\s*['\"]",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(r"(\.\./){2,}|(\.\.\\){2,}"),
    "null_byte_or_encoded_control": re.compile(r"%00|\\x00|\x00"),
    # A long run of the same repeated character is a classic buffer-overflow
    # / fuzzing probe signature, not something a human or a real API emits.
    "overflow_probe": re.compile(r"(.)\1{40,}"),
}


def find_security_flags(line: str):
    """Return a list of (flag_name) for every suspicious pattern a line
    trips. Empty list means the line looks safe to process normally."""
    flags = []
    for name, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(line):
            flags.append(name)
    return flags


# ---------------------------------------------------------------------------
# SECTION 2: EXTRACTION PATTERNS
# ---------------------------------------------------------------------------

# --- Email -------------------------------------------------------------
# General, realistic email pattern (RFC-5322 "practical subset"): local
# part allows letters, digits, ., _, %, +, - ; domain allows subdomains.
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)+\b"
)

# ALU-specific domain classification, applied AFTER a string already
# matched EMAIL_PATTERN (so we never classify something that wasn't even a
# validly-formed email in the first place). Ordered most-specific first,
# since "alumni.alueducation.com" and "si.alueducation.com" also end with
# "alueducation.com".
ALU_DOMAIN_RULES = [
    ("alu_alumni", re.compile(r"@alumni\.alueducation\.com$", re.IGNORECASE)),
    ("alu_si", re.compile(r"@si\.alueducation\.com$", re.IGNORECASE)),
    ("alu_official", re.compile(r"@alueducation\.com$", re.IGNORECASE)),
]


def classify_email(email: str) -> str:
    for label, pattern in ALU_DOMAIN_RULES:
        if pattern.search(email):
            return label
    return "general"


# --- Phone numbers -------------------------------------------------------
# Covers: +250 788 123 456 | (617) 555-0192 | 617.555.0199 | 0788-123-456
# | +250 (788) 999 222 | 1-800-555-0147 ext. 2210
# Shape: optional country/trunk code, optional parenthesized area code,
# then 2-3 digit blocks (handles both "area-exchange-line" numbers with no
# separate parens, and "exchange-line" numbers when the area code was
# already consumed by the parenthesized group), plus an optional extension.
PHONE_PATTERN = re.compile(
    r"(?<!\d)"
    r"(?:\+?\d{1,3}[-.\s]?)?"                 # optional country/trunk code
    r"(?:\(\d{2,4}\)[-.\s]?)?"                # optional (area code)
    r"\d{3,4}(?:[-.\s]?\d{3,4}){1,2}"         # 2-3 number blocks
    r"(?:\s?(?:ext\.?|x)\s?\d{2,5})?"         # optional extension
    r"(?!\d)"
)

# A phone candidate must contain at least 7 digits to be a real number
# (filters out short false-positives like a lone date fragment).
def digit_count(s: str) -> int:
    return len(re.findall(r"\d", s))


# --- Credit cards ----------------------------------------------------------
# Candidate shape: 4 blocks of digits, grouped like real cards, separated
# by spaces/dashes/nothing, or Amex-style 4-6-5. We then Luhn-check the
# digits so we don't report a well-formatted but fake/mistyped number as
# a valid card.
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:\d{4}[ -]?\d{6}[ -]?\d{5}"      # Amex: 4-6-5
    r"|\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7})\b"  # Visa/MC/etc: 4-4-4-(1..7)
)


def luhn_is_valid(digits: str) -> bool:
    """Standard Luhn checksum used by all major card networks."""
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask_card(digits: str) -> str:
    """Never expose the full PAN in output/logs - only last 4 digits."""
    return "*" * (len(digits) - 4) + digits[-4:]


# --- URLs --------------------------------------------------------------
URL_PATTERN = re.compile(
    r"\bhttps?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s'\"<>]*)?", re.IGNORECASE
)

# --- IPv4 (validated octet ranges, so 999.999.999.999 is correctly
# rejected instead of naively matching \d{1,3} four times) -----------------
_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4_PATTERN = re.compile(rf"\b{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}\b")

# --- Dates (ISO 2026-09-15 and US-style 09/07/2026) ------------------------
DATE_PATTERN = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2})\b|\b(?:\d{1,2}/\d{1,2}/\d{4})\b"
)


def is_plausible_date(text: str) -> bool:
    """Reject calendar-impossible dates (regex alone can't catch Feb 30)."""
    for fmt in ("%Y-%m-%d", "%m/%d/%Y"):
        try:
            datetime.strptime(text, fmt)
            return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# SECTION 3: LINE-BY-LINE PROCESSING
# ---------------------------------------------------------------------------

def _overlaps(span, claimed_spans):
    start, end = span
    for c_start, c_end in claimed_spans:
        if start < c_end and end > c_start:
            return True
    return False


def process_line(line: str, results: dict, rejected: list, line_no: int):
    flags = find_security_flags(line)
    if flags:
        # Do NOT extract from a flagged line - log it, don't trust it.
        rejected.append({
            "line_number": line_no,
            "reason": flags,
            # We store only a short, safe preview - not the raw payload -
            # so the report itself can't be used to replay the attack.
            "preview": line.strip()[:60] + ("..." if len(line.strip()) > 60 else ""),
        })
        return

    # We extract in priority order and "claim" the character span each
    # match occupies. Lower-priority extractors (phone numbers especially,
    # since its digit-block shape is broad) skip anything already claimed
    # by a more specific pattern, so a credit card or IP address can never
    # also get reported as a phone number.
    claimed_spans = []

    # 1) Emails (most specific token shape - claim first)
    for m in EMAIL_PATTERN.finditer(line):
        email = m.group(0)
        category = classify_email(email)
        results["emails"].setdefault(category, [])
        if email not in results["emails"][category]:
            results["emails"][category].append(email)
        claimed_spans.append(m.span())

    # 2) URLs
    for m in URL_PATTERN.finditer(line):
        url = m.group(0).rstrip(").,")
        secure = url.lower().startswith("https://")
        entry = {"url": url, "https": secure}
        if entry not in results["urls"]:
            results["urls"].append(entry)
        claimed_spans.append(m.span())

    # 3) IPv4 addresses (validated octet ranges - a bogus quad like
    #    999.999.999.999 simply will not match this pattern at all)
    for m in IPV4_PATTERN.finditer(line):
        ip = m.group(0)
        if ip not in results["ip_addresses"]:
            results["ip_addresses"].append(ip)
        claimed_spans.append(m.span())

    # 4) Credit cards (claim before phone numbers, since a 16-digit card
    #    is a superset shape of a phone number's digit blocks)
    for m in CREDIT_CARD_PATTERN.finditer(line):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if len(digits) < 13 or len(digits) > 19:
            continue
        valid = luhn_is_valid(digits)
        entry = {"masked": mask_card(digits), "luhn_valid": valid}
        if entry not in results["credit_cards"]:
            results["credit_cards"].append(entry)
        claimed_spans.append(m.span())

    # 5) Dates
    for m in DATE_PATTERN.finditer(line):
        date_str = m.group(0)
        if is_plausible_date(date_str):
            if date_str not in results["dates"]:
                results["dates"].append(date_str)
            claimed_spans.append(m.span())

    # 6) Phone numbers - lowest priority; skip anything already claimed
    #    above, and skip bogus dotted-quad shapes (3 dots / 4 groups),
    #    which are IP-shaped, not phone-shaped, even when not a valid IP.
    for m in PHONE_PATTERN.finditer(line):
        if _overlaps(m.span(), claimed_spans):
            continue
        candidate = m.group(0).strip()
        if candidate.count(".") == 3 and re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", candidate):
            continue  # IP-shaped junk (valid or not) is not a phone number
        if digit_count(candidate) >= 7 and candidate not in results["phone_numbers"]:
            results["phone_numbers"].append(candidate)


# ---------------------------------------------------------------------------
# SECTION 4: MAIN
# ---------------------------------------------------------------------------

def run(input_path: str, output_path: str):
    if not os.path.exists(input_path):
        print(f"ERROR: input file not found: {input_path}")
        sys.exit(1)

    results = {
        "emails": {},          # category -> [emails]
        "phone_numbers": [],
        "credit_cards": [],    # [{masked, luhn_valid}]
        "urls": [],            # [{url, https}]
        "ip_addresses": [],
        "dates": [],
    }
    rejected_lines = []

    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        for i, raw_line in enumerate(f, start=1):
            process_line(raw_line, results, rejected_lines, i)

    report = {
        "summary": {
            "total_emails": sum(len(v) for v in results["emails"].values()),
            "total_phone_numbers": len(results["phone_numbers"]),
            "total_credit_cards_detected": len(results["credit_cards"]),
            "valid_credit_cards": sum(1 for c in results["credit_cards"] if c["luhn_valid"]),
            "total_urls": len(results["urls"]),
            "total_ip_addresses": len(results["ip_addresses"]),
            "total_dates": len(results["dates"]),
            "lines_rejected_as_unsafe": len(rejected_lines),
        },
        "extracted": results,
        "rejected_lines": rejected_lines,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(report, out, indent=2)

    # Console summary (never prints full raw card numbers or attack payloads)
    print("=" * 60)
    print("REGEX EXTRACTION & VALIDATION - SUMMARY")
    print("=" * 60)
    for key, value in report["summary"].items():
        print(f"{key:35s}: {value}")
    print("-" * 60)
    print(f"Full structured results written to: {output_path}")
    if rejected_lines:
        print(f"\n{len(rejected_lines)} line(s) were flagged as unsafe and skipped:")
        for r in rejected_lines:
            print(f"  - line {r['line_number']} ({', '.join(r['reason'])})")


if __name__ == "__main__":
    default_input = os.path.join(os.path.dirname(__file__), "..", "input", "raw-text.txt")
    default_output = os.path.join(os.path.dirname(__file__), "..", "output", "sample-output.json")
    in_path = sys.argv[1] if len(sys.argv) > 1 else default_input
    out_path = sys.argv[2] if len(sys.argv) > 2 else default_output
    run(in_path, out_path)

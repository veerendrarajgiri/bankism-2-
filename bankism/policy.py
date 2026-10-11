"""Small deterministic rules shared by the firewall AND the transaction handler."""
import html
import re
import unicodedata
from decimal import Decimal, InvalidOperation
from typing import Optional, Tuple

import config


def check_amount(amount, limit: Decimal, balance: Optional[Decimal] = None) -> Optional[Tuple[str, str]]:
    """Return (code, message) if the amount is not allowed, else None."""
    if isinstance(amount, bool) or not isinstance(amount, Decimal):
        return "INVALID_AMOUNT", "Amount must be a decimal number."
    if not amount.is_finite():
        return "INVALID_AMOUNT", "Amount must be a finite number."
    if amount <= 0:
        return "INVALID_AMOUNT", "Amount must be greater than zero."
    try:
        if amount != amount.quantize(Decimal("0.01")):
            return "INVALID_AMOUNT", "Amount can have at most 2 decimal places."
    except InvalidOperation:
        return "LIMIT_EXCEEDED", "Amount is far above the demo transfer limit."
    if amount > limit:
        return "LIMIT_EXCEEDED", f"Amount exceeds the demo transfer limit of {format_inr(limit)}."
    if balance is not None and amount > balance:
        return "INSUFFICIENT_FUNDS", "Amount is higher than the available balance."
    return None


def check_memo(memo) -> Optional[str]:
    """Return an error message if the memo is not acceptable, else None."""
    if not isinstance(memo, str):
        return "Memo must be text."
    if len(memo) > config.MAX_MEMO_LENGTH:
        return f"Memo is too long (max {config.MAX_MEMO_LENGTH} characters)."
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn") for c in memo):
        return "Memo contains hidden or control characters."
    return None


_PHONE_ALLOWED_CHARS = re.compile(r"^[\d\s+\-().]+$")


def check_phone_number(phone) -> Optional[Tuple[str, str]]:
    """Return (code, message) if the phone number is invalid or incomplete, else None."""
    if not isinstance(phone, str) or not phone.strip():
        return "INVALID_PHONE", "Phone number cannot be empty."
    cleaned = phone.strip()
    if not _PHONE_ALLOWED_CHARS.match(cleaned):
        return "INVALID_PHONE", "Phone number contains invalid characters. Only digits, +, -, and spaces are allowed."
    digits = [c for c in cleaned if c.isdigit()]
    if len(digits) < 10:
        return "INCOMPLETE_PHONE", f"Phone number is incomplete (got {len(digits)} digits, minimum 10 digits required)."
    if len(digits) > 15:
        return "INVALID_PHONE", f"Phone number is too long (got {len(digits)} digits, maximum 15 digits allowed)."
    if len(set(digits)) == 1:
        return "INVALID_PHONE", "Phone number cannot consist of identical repeating digits."
    if len(digits) == 10 and not cleaned.startswith("+") and digits[0] in "01":
        return "INVALID_PHONE", "10-digit mobile number must start with a valid digit (6–9)."
    return None


def normalize_phone_number(phone: str) -> str:
    """Normalize phone number for clean presentation and storage."""
    cleaned = str(phone).strip()
    digits = "".join(c for c in cleaned if c.isdigit())
    if len(digits) == 10:
        return f"+91 {digits[:5]} {digits[5:]}"
    if len(digits) == 11 and digits.startswith("0"):
        d = digits[1:]
        return f"+91 {d[:5]} {d[5:]}"
    if len(digits) == 12 and digits.startswith("91"):
        d = digits[2:]
        return f"+91 {d[:5]} {d[5:]}"
    if cleaned.startswith("+"):
        return "+" + digits
    return digits


_REDACTIONS = [
    (re.compile(r"(?i)\b(pin|passcode|password|otp|cvv|secret)\b(\W{0,12}(?:is\s+|=\s*)?)\d{3,8}\b"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\b(?:sk|api|key)[-_][A-Za-z0-9_\-]{10,}"), "[REDACTED-KEY]"),
    (re.compile(r"\b\d{9,}\b"), "[REDACTED-NUMBER]"),
]


def redact_sensitive(text: str, max_len: int = 240) -> str:
    """Remove PIN-like values, keys and long numbers before logging / sending to an LLM."""
    out = str(text)
    for rx, repl in _REDACTIONS:
        out = rx.sub(repl, out)
    return out[:max_len]


def format_inr(amount) -> str:
    """12345.5 -> ₹12,345.50 (Indian digit grouping)."""
    q = Decimal(amount).quantize(Decimal("0.01"))
    sign = "-" if q < 0 else ""
    whole, frac = f"{abs(q):.2f}".split(".")
    if len(whole) > 3:
        head, tail, groups = whole[:-3], whole[-3:], []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        whole = ",".join(groups + [tail])
    return f"{sign}₹{whole}.{frac}"


def md_escape(text) -> str:
    """Make untrusted text safe to place inside Markdown (no links, HTML or formatting)."""
    t = html.escape(str(text).replace("\n", " "), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|~$>:])", r"\\\1", t)

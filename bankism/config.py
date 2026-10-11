"""Central configuration. DEMO VALUES ONLY - nothing here is a real credential."""
import os
from datetime import timedelta, timezone
from decimal import Decimal, InvalidOperation

from models import Contact

APP_NAME = "BANKISM"
APP_SUBTITLE = "AI Banking Security Firewall"
IST = timezone(timedelta(hours=5, minutes=30))


def _env_decimal(name: str, default: str) -> Decimal:
    try:
        value = Decimal(os.environ.get(name, default))
        if value.is_finite() and value > 0:
            return value
    except (InvalidOperation, TypeError):
        pass
    return Decimal(default)


# --- Demo bank account -------------------------------------------------------
ACCOUNT_HOLDER = "Alex Morgan"
ACCOUNT_MASKED = "XXXX XXXX 4821"
CURRENCY = "INR"
OPENING_BALANCE = Decimal("25000.00")
DEMO_TRANSFER_LIMIT = _env_decimal("BANKISM_TRANSFER_LIMIT", "5000")  # per transfer
DEMO_PIN = "4826"          # FICTIONAL demo PIN. Never use a hardcoded PIN in a real bank.
MAX_PIN_ATTEMPTS = 3

# --- Firewall limits ----------------------------------------------------------
MAX_INPUT_LENGTH = 500
MAX_MEMO_LENGTH = 60
HISTORY_DEFAULT_COUNT = 5
HISTORY_MAX_COUNT = 20

# --- Optional LLM second opinion (key comes from the environment only) ---------
LLM_TIMEOUT_SECONDS = 8
LLM_MODEL = os.environ.get("BANKISM_LLM_MODEL", "claude-haiku-5-5")

DEMO_CONTACTS = (
    Contact(id="C001", name="Rahul Verma", masked_account="XXXX 1042", phone="+91 98765 43210"),
    Contact(id="C002", name="Maya Sharma", masked_account="XXXX 2087", phone="+91 98765 43211"),
    Contact(id="C003", name="Ananya Rao", masked_account="XXXX 3319", phone="+91 98765 43212"),
    Contact(id="C004", name="Arjun Mehta", masked_account="XXXX 6745", phone="+91 98765 43213"),
    Contact(id="C005", name="Priya Nair", masked_account="XXXX 9051", phone="+91 98765 43214"),
)

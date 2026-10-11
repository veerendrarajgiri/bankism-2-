"""The ONLY place where demo money moves: BankAccount.execute_transfer().

It re-validates everything itself (recipient, amount, limit, balance, confirmation, PIN)
and is idempotent, so a double click or a Streamlit re-run can never pay twice.
"""
import hmac
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Tuple

import config
from models import ActionType, Contact, Decision, PolicyContext, Verdict
from policy import check_amount, check_memo, check_phone_number, format_inr, normalize_phone_number


RETRYABLE_CODES = frozenset({"PIN_INVALID", "NOT_CONFIRMED"})


class TransferError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


@dataclass(frozen=True)
class Transaction:
    txn_id: str
    timestamp: datetime
    direction: str            # SENT | RECEIVED
    contact_id: Optional[str]
    contact_name: str
    amount: Decimal
    memo: str
    source: str               # "SEEDED DEMO" | "SESSION"
    recipient_phone: Optional[str] = None


@dataclass
class PendingTransfer:
    transfer_id: str
    contact_id: Optional[str]
    amount: Decimal
    memo: str
    created_at: datetime
    status: str = "PENDING"   # PENDING | EXECUTED | CANCELLED | REJECTED
    recipient_phone: Optional[str] = None
    recipient_name: Optional[str] = None
    verdict: Optional[Verdict] = None



@dataclass(frozen=True)
class TransferResult:
    success: bool
    code: str
    message: str
    transaction: Optional[Transaction] = None
    balance: Optional[Decimal] = None


class BankAccount:
    """Session-based simulated account. Demo data only; resets with the session."""

    def __init__(self, pin: str = config.DEMO_PIN, opening_balance: Decimal = config.OPENING_BALANCE,
                 limit: Decimal = config.DEMO_TRANSFER_LIMIT, contacts=config.DEMO_CONTACTS):
        self.holder, self.masked_account, self.currency = config.ACCOUNT_HOLDER, config.ACCOUNT_MASKED, config.CURRENCY
        self._pin = pin
        self._balance = Decimal(opening_balance).quantize(Decimal("0.01"))
        self._limit = Decimal(limit)
        self._contacts: Dict[str, Contact] = {c.id: c for c in contacts}
        self._pending: Dict[str, PendingTransfer] = {}
        self._failed_attempts = 0
        self._lock = threading.Lock()
        self._counter = 0
        self._ledger: List[Transaction] = []
        self._seed()

    # ---- seeded history: records only, they NEVER change the opening balance
    def _seed(self):
        now = datetime.now(config.IST)
        rows = [(1, "SENT", "C001", 500, "Lunch"), (1, "SENT", "C002", 1200, "Shared expenses"),
                (2, "SENT", "C003", 250, "Coffee"), (3, "RECEIVED", "C004", 2000, "Reimbursement"),
                (4, "SENT", "C005", 750, "Books")]
        for i, (days, direction, cid, amt, memo) in enumerate(rows, 1):
            self._ledger.append(Transaction(f"SEED-{i:03d}", now - timedelta(days=days, minutes=i * 7), direction, cid,
                                            self._contacts[cid].name, Decimal(amt).quantize(Decimal("0.01")), memo, "SEEDED DEMO"))

    # ---- read-only views
    @property
    def balance(self) -> Decimal:
        return self._balance

    @property
    def limit(self) -> Decimal:
        return self._limit

    @property
    def contacts(self):
        return tuple(self._contacts.values())

    @property
    def locked(self) -> bool:
        return self._failed_attempts >= config.MAX_PIN_ATTEMPTS

    @property
    def attempts_left(self) -> int:
        return max(0, config.MAX_PIN_ATTEMPTS - self._failed_attempts)

    @property
    def session_transfers(self) -> int:
        return sum(1 for t in self._ledger if t.source == "SESSION")

    def ledger(self) -> List[Transaction]:
        return sorted(self._ledger, key=lambda t: t.timestamp, reverse=True)

    def recent(self, n: int) -> List[Transaction]:
        return self.ledger()[:n]

    def get_contact(self, contact_id: str) -> Optional[Contact]:
        return self._contacts.get(contact_id)

    def get_pending(self, transfer_id: Optional[str]) -> Optional[PendingTransfer]:
        return self._pending.get(transfer_id) if transfer_id else None

    @property
    def pending_count(self) -> int:
        return sum(1 for p in self._pending.values() if p.status == "PENDING")

    def policy_context(self) -> PolicyContext:

        return PolicyContext(balance=self._balance, limit=self._limit, contacts=self.contacts)

    # ---- pending transfers
    def create_pending(self, verdict: Verdict) -> PendingTransfer:
        """Only an APPROVED verdict with a TRANSFER action can become a pending transfer."""
        a = verdict.action
        if verdict.decision != Decision.APPROVE or a is None or a.type != ActionType.TRANSFER:
            raise TransferError("NOT_APPROVED", "Only an approved transfer request can be prepared.")
        if a.contact_id is not None:
            if a.contact_id not in self._contacts:
                raise TransferError("UNKNOWN_RECIPIENT", "Unknown recipient.")
            contact = self._contacts[a.contact_id]
            phone = a.recipient_phone or getattr(contact, "phone", None)
            recip_name = a.contact_name or contact.name
        else:
            if not a.recipient_phone:
                raise TransferError("UNKNOWN_RECIPIENT", "Recipient is missing.")
            phone_err = check_phone_number(a.recipient_phone)
            if phone_err:
                raise TransferError(phone_err[0], phone_err[1])
            phone = normalize_phone_number(a.recipient_phone)
            recip_name = a.contact_name or phone
        err = check_amount(a.amount, self._limit, self._balance)
        if err:
            raise TransferError(*err)
        merr = check_memo(a.memo or "")
        if merr:
            raise TransferError("INVALID_MEMO", merr)
        p = PendingTransfer(
            uuid.uuid4().hex, a.contact_id, a.amount, a.memo or "Transfer",
            datetime.now(config.IST), "PENDING", recipient_phone=phone, recipient_name=recip_name,
            verdict=verdict
        )
        self._pending[p.transfer_id] = p
        return p


    def cancel_pending(self, transfer_id: Optional[str]) -> None:
        p = self._pending.get(transfer_id) if transfer_id else None
        if p and p.status == "PENDING":
            p.status = "CANCELLED"

    # ---- THE transaction handler
    def execute_transfer(self, transfer_id, entered_pin, confirmed, confirm_contact_id, confirm_amount) -> TransferResult:
        with self._lock:
            if self.locked:
                return self._fail("LOCKED", "Too many incorrect PIN attempts. The demo account is locked; reset the demo session.")
            p = self._pending.get(transfer_id)
            if p is None:
                return self._fail("UNKNOWN_TRANSFER", "No such pending transfer.")
            if p.status == "EXECUTED":
                return self._fail("DUPLICATE", "This transfer was already completed. No money was moved again.")
            if p.status != "PENDING":
                return self._fail("NOT_PENDING", "This transfer is no longer pending.")
            if confirmed is not True:
                return self._fail("NOT_CONFIRMED", "Please tick the confirmation box for the exact recipient and amount.")
            if confirm_contact_id != p.contact_id or confirm_amount != p.amount:
                p.status = "REJECTED"
                return self._fail("MISMATCH", "Confirmed details do not match the pending transfer. It was cancelled.")
            if not self._pin_ok(entered_pin):
                self._failed_attempts += 1
                left = self.attempts_left
                return self._fail("PIN_INVALID", "Incorrect PIN. " + (f"{left} attempt(s) left." if left else "The demo account is now locked."))
            # --- re-validate everything, even though earlier stages already did
            if p.contact_id is not None:
                if p.contact_id not in self._contacts:
                    return self._reject(p, "UNKNOWN_RECIPIENT", "Unknown recipient.")
                recip_name = self._contacts[p.contact_id].name
                phone = p.recipient_phone or getattr(self._contacts[p.contact_id], "phone", None)
            else:
                if not p.recipient_phone:
                    return self._reject(p, "UNKNOWN_RECIPIENT", "Recipient is missing.")
                phone_err = check_phone_number(p.recipient_phone)
                if phone_err:
                    return self._reject(p, phone_err[0], phone_err[1])
                recip_name = p.recipient_name or p.recipient_phone
                phone = p.recipient_phone
            err = check_amount(p.amount, self._limit, self._balance)
            if err:
                return self._reject(p, *err)
            merr = check_memo(p.memo)
            if merr:
                return self._reject(p, "INVALID_MEMO", merr)
            # --- execute
            self._failed_attempts = 0
            self._balance -= p.amount
            self._counter += 1
            txn = Transaction(f"TXN-{self._counter:04d}", datetime.now(config.IST), "SENT", p.contact_id,
                              recip_name, p.amount, p.memo, "SESSION", recipient_phone=phone)
            self._ledger.append(txn)
            p.status = "EXECUTED"
            return TransferResult(True, "OK", "Transfer completed.", txn, self._balance)

    def set_transfer_limit(self, new_limit: Decimal, entered_pin: str) -> Tuple[bool, str, Decimal]:
        """Update the per-transfer limit after validating the demo PIN."""
        with self._lock:
            if self.locked:
                return False, "Too many incorrect PIN attempts. The demo account is locked; reset the demo session.", self._limit
            if not isinstance(new_limit, Decimal) or not new_limit.is_finite() or new_limit <= Decimal("0"):
                return False, "Limit must be a positive number greater than zero.", self._limit
            try:
                new_limit = new_limit.quantize(Decimal("0.01"))
            except Exception:
                return False, "Limit can have at most 2 decimal places.", self._limit
            if not self._pin_ok(entered_pin):
                self._failed_attempts += 1
                left = self.attempts_left
                msg = "Incorrect PIN. " + (f"{left} attempt(s) left." if left else "The demo account is now locked.")
                return False, msg, self._limit
            self._failed_attempts = 0
            self._limit = new_limit
            return True, f"Transfer limit updated to {format_inr(self._limit)}.", self._limit

    def _pin_ok(self, entered) -> bool:
        if not isinstance(entered, str) or not entered.isascii() or not entered.isdigit() or not 4 <= len(entered) <= 8:
            return False
        return hmac.compare_digest(entered.encode(), self._pin.encode())   # constant-time compare

    def _fail(self, code, message) -> TransferResult:
        return TransferResult(False, code, message, None, self._balance)

    def _reject(self, p, code, message) -> TransferResult:
        p.status = "REJECTED"
        return self._fail(code, message)


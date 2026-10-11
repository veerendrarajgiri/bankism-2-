import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import List, Optional

import config
from audit import AuditLog
from models import ActionType, Contact, Decision, Intent, Verdict
from policy import format_inr, md_escape
from security import analyze_request, analyze_transfer_form
from transaction_engine import BankAccount, PendingTransfer, TransferError, TransferResult



@dataclass
class ChatReply:
    text: str
    verdict: Verdict
    pending: Optional[PendingTransfer] = None
    candidates: List[Contact] = field(default_factory=list)
    proposed_limit: Optional[Decimal] = None



def _history_lines(account: BankAccount, n: int) -> str:
    lines = []
    for t in account.recent(n):
        way = "Sent to" if t.direction == "SENT" else "Received from"
        tag = "seeded demo" if t.source == "SEEDED DEMO" else "this session"
        lines.append(f"- {t.timestamp:%d %b %H:%M} · {way} **{md_escape(t.contact_name)}** · {format_inr(t.amount)} · "
                     f"{md_escape(t.memo)} · _{tag}_")
    return "\n".join(lines)


def _compose(v: Verdict, account: BankAccount, pending: Optional[PendingTransfer], err: Optional[TransferError]) -> str:
    if err:
        return f"🛑 **Blocked** — {err.message} No money was moved."
    if v.decision == Decision.BLOCK:
        return f"🛑 **Blocked** — {v.rationale}"
    if v.decision == Decision.REVIEW:
        return f"⚠️ **Needs review** — {v.rationale}"
    if v.decision == Decision.CLARIFICATION_REQUIRED:
        extra = ""
        if v.intent == Intent.UNKNOWN:
            extra = (f"\n\nTry: *What's my balance?*, *Show my last five transactions*, or *Send ₹500 to Rahul for lunch*. "
                     f"Transfers are limited to {format_inr(account.limit)} each.")
        if v.candidates:
            extra += "\n\nPlease pick the intended contact below."
        return f"🟡 **Clarification needed** — {v.rationale}{extra}"
    a = v.action
    if a is None:
        if "quoted_phrase_discussed" in v.signals:
            return ("✅ **Approved (informational)** — That phrase is a classic prompt-injection example. "
                    "BANKISM treats quoted text as data and never as an instruction, so nothing was executed.")
        return ("✅ Hello! I'm the BANKISM security assistant. I can show your balance, list recent transactions, "
                f"or prepare a transfer (max {format_inr(account.limit)}). Every request goes through the firewall first.")
    if a.type == ActionType.BALANCE_INQUIRY:
        return f"✅ **Approved (read-only)** — Your demo balance is **{format_inr(account.balance)}** (account {account.masked_account})."
    if a.type == ActionType.TRANSACTION_HISTORY:
        return f"✅ **Approved (read-only)** — Your last {a.count} transactions:\n\n{_history_lines(account, a.count)}"
    if pending:
        recip_label = pending.recipient_name or (a.contact_name if a else None) or pending.recipient_phone or "the recipient"
        phone_suffix = f" ({pending.recipient_phone})" if pending.recipient_phone and pending.recipient_phone != recip_label else ""
        return (f"✅ **Passed analysis** — I prepared a transfer of **{format_inr(pending.amount)}** to "
                f"**{md_escape(recip_label)}**{phone_suffix} (memo: {md_escape(pending.memo)}). **Nothing has been sent yet.** "
                "Review the details below, enter the demo PIN and press *Confirm Transfer*.")
    return "⚠️ Could not prepare the transfer."


def _finish(logged_text: str, verdict: Verdict, account: BankAccount, audit: AuditLog) -> ChatReply:
    audit.record_analysis(logged_text, verdict)
    pending, err = None, None
    if verdict.decision == Decision.APPROVE and verdict.intent == Intent.TRANSFER:
        try:
            pending = account.create_pending(verdict)
        except TransferError as exc:
            err = exc
    return ChatReply(_compose(verdict, account, pending, err), verdict, pending, list(verdict.candidates))


_LIMIT_CHANGE_RX = re.compile(
    r"\b(?:change|set|update|increase|raise|lower|reduce|make)\b(?:\W+\w+){0,3}?\W+(?:limit|transfer\s+limit|transaction\s+limit)\b"
    r"|(?:\b(?:limit|transfer\s+limit|transaction\s+limit)\s*(?:to|=|is)\s*)",
    re.I
)
_NUM_CLEAN_RX = re.compile(r"[₹,]|(?:inr|rs\.?)", re.I)


def _detect_limit_request(text: str) -> Optional[Decimal]:
    if not isinstance(text, str):
        return None
    if not _LIMIT_CHANGE_RX.search(text):
        return None
    # Extract numerical candidate from the text
    matches = re.findall(r"(?:₹|inr|rs\.?)?\s*([0-9]+(?:,[0-9]+)*(?:\.[0-9]{1,2})?)", text, re.I)
    for m in matches:
        cleaned = _NUM_CLEAN_RX.sub("", m).replace(",", "").strip()
        try:
            val = Decimal(cleaned)
            if val.is_finite() and val > 0:
                return val.quantize(Decimal("0.01"))
        except (InvalidOperation, Exception):
            continue
    return None


def handle_message(text, account: BankAccount, audit: AuditLog, llm=None) -> ChatReply:
    verdict = analyze_request(text, account.policy_context(), llm)
    # Check if this is a request to adjust the transaction limit
    if verdict.decision != Decision.BLOCK:
        proposed = _detect_limit_request(text)
        if proposed is not None:
            msg = (
                f"⚙️ **Transfer Limit Adjustment** — You requested to change your per-transfer limit to **{format_inr(proposed)}** "
                f"(current limit is **{format_inr(account.limit)}**).\n\n"
                "🛡️ To protect your account, limit modifications require explicit demo PIN verification. "
                "Please enter the demo PIN below to authorize this change."
            )
            audit.record_analysis(text if isinstance(text, str) else repr(text)[:80], verdict)
            return ChatReply(msg, verdict, None, [], proposed_limit=proposed)
    return _finish(text if isinstance(text, str) else repr(text)[:80], verdict, account, audit)



def handle_transfer_form(contact_id, amount, memo, account: BankAccount, audit: AuditLog, llm=None,
                         recipient_phone: Optional[str] = None, recipient_name: Optional[str] = None) -> ChatReply:
    verdict = analyze_transfer_form(contact_id, amount, memo, account.policy_context(), llm,
                                    recipient_phone=recipient_phone, recipient_name=recipient_name)
    recip_info = contact_id or recipient_phone or "unknown"
    logged = f"[form] recipient={recip_info} amount={amount} memo={memo}"
    return _finish(logged, verdict, account, audit)


def success_message(result: TransferResult) -> str:
    t = result.transaction
    phone_info = f" ({t.recipient_phone})" if t.recipient_phone and t.recipient_phone != t.contact_name else ""
    return (f"✅ **Transfer completed** (ref {t.txn_id}) — {format_inr(t.amount)} sent to **{md_escape(t.contact_name)}**{phone_info}. "
            f"New demo balance: **{format_inr(result.balance)}**.")

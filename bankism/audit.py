"""Security event log. Stores REDACTED text only (never the PIN)."""
from datetime import datetime
from decimal import Decimal
from typing import List, Optional

from pydantic import BaseModel, Field

import config
from models import Decision, Intent, RiskLevel, ThreatCategory, Verdict
from policy import format_inr, redact_sensitive


class SecurityEvent(BaseModel):
    event_id: int
    timestamp: datetime
    event_type: str            # REQUEST_ANALYSIS | TRANSFER_EXECUTED | TRANSFER_REJECTED
    request: str               # redacted
    decision: Decision
    risk_level: RiskLevel
    threat_category: ThreatCategory
    intent: Intent
    rationale: str
    signals: List[str] = Field(default_factory=list)
    recipient_phone: Optional[str] = None


class AuditLog:
    def __init__(self):
        self.events: List[SecurityEvent] = []

    def _add(self, **kw) -> SecurityEvent:
        ev = SecurityEvent(event_id=len(self.events) + 1, timestamp=datetime.now(config.IST), **kw)
        self.events.append(ev)
        return ev

    def record_analysis(self, text, verdict: Verdict) -> SecurityEvent:
        phone = verdict.action.recipient_phone if (verdict.action and hasattr(verdict.action, "recipient_phone")) else None
        return self._add(event_type="REQUEST_ANALYSIS", request=redact_sensitive(text), decision=verdict.decision,
                         risk_level=verdict.risk_level, threat_category=verdict.threat_category, intent=verdict.intent,
                         rationale=verdict.rationale, signals=verdict.signals, recipient_phone=phone)

    def record_transfer(self, result, pending, contact_name: str, recipient_phone: Optional[str] = None) -> SecurityEvent:
        ok = result.success
        phone = recipient_phone or getattr(pending, "recipient_phone", None)
        phone_suffix = f" ({phone})" if phone and phone not in contact_name else ""
        what = f"{format_inr(pending.amount)} to {contact_name}{phone_suffix}"
        return self._add(
            event_type="TRANSFER_EXECUTED" if ok else "TRANSFER_REJECTED", request=f"Confirm transfer: {what}",
            decision=Decision.APPROVE if ok else Decision.BLOCK,
            risk_level=RiskLevel.LOW if ok else RiskLevel.MEDIUM,
            threat_category=ThreatCategory.NONE if ok else ThreatCategory.AUTHORIZATION_FAILURE
            if result.code in ("PIN_INVALID", "NOT_CONFIRMED", "LOCKED", "MISMATCH") else ThreatCategory.INVALID_TRANSACTION,
            intent=Intent.TRANSFER, rationale=result.message, signals=[result.code.lower()],
            recipient_phone=phone)

    def record_limit_change(self, success: bool, new_limit: Decimal, message: str) -> SecurityEvent:
        return self._add(
            event_type="LIMIT_UPDATED" if success else "LIMIT_UPDATE_BLOCKED",
            request=f"Update per-transfer limit to {format_inr(new_limit)}",
            decision=Decision.APPROVE if success else Decision.BLOCK,
            risk_level=RiskLevel.LOW if success else RiskLevel.MEDIUM,
            threat_category=ThreatCategory.NONE if success else ThreatCategory.AUTHORIZATION_FAILURE,
            intent=Intent.UNKNOWN,
            rationale=message,
            signals=["limit_updated" if success else "limit_update_denied"],
            recipient_phone=None,
        )


    def metrics(self) -> dict:
        """Counts of analysed REQUESTS, computed from real events."""
        reqs = [e for e in self.events if e.event_type == "REQUEST_ANALYSIS"]
        return {
            "approved": sum(e.decision == Decision.APPROVE for e in reqs),
            "blocked": sum(e.decision == Decision.BLOCK for e in reqs),
            "review": sum(e.decision in (Decision.REVIEW, Decision.CLARIFICATION_REQUIRED) for e in reqs),
            "total": len(reqs),
        }

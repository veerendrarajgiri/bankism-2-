"""Pydantic models shared by the whole app (verdicts, actions, contacts)."""
from decimal import Decimal
from enum import Enum
from typing import List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Decision(str, Enum):
    APPROVE = "APPROVE"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    CLARIFICATION_REQUIRED = "CLARIFICATION_REQUIRED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    POLICY_OVERRIDE = "POLICY_OVERRIDE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    OBFUSCATION = "OBFUSCATION"
    AMBIGUOUS_REQUEST = "AMBIGUOUS_REQUEST"
    INVALID_TRANSACTION = "INVALID_TRANSACTION"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    # Extra values added on top of the required schema:
    INVALID_INPUT = "INVALID_INPUT"          # not text / too long / malformed
    ANALYSIS_FAILURE = "ANALYSIS_FAILURE"    # security analysis itself failed (fail closed)


class Intent(str, Enum):
    BALANCE_INQUIRY = "BALANCE_INQUIRY"
    TRANSACTION_HISTORY = "TRANSACTION_HISTORY"
    TRANSFER = "TRANSFER"
    UNKNOWN = "UNKNOWN"


class ActionType(str, Enum):
    BALANCE_INQUIRY = "BALANCE_INQUIRY"
    TRANSACTION_HISTORY = "TRANSACTION_HISTORY"
    TRANSFER = "TRANSFER"


class Contact(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    name: str
    masked_account: str
    phone: Optional[str] = None


class Action(BaseModel):
    """Structured, already-validated description of what the user wants."""
    type: ActionType
    contact_id: Optional[str] = None
    contact_name: Optional[str] = None
    recipient_phone: Optional[str] = None
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    memo: Optional[str] = None
    count: Optional[int] = None


class TransferDraft(BaseModel):
    """Partial transfer details kept while we ask the user to clarify."""
    amount: Optional[Decimal] = None
    memo: str = ""


class Verdict(BaseModel):
    """The firewall's JSON verdict for one analysed request."""
    model_config = ConfigDict(extra="forbid")

    decision: Decision
    risk_level: RiskLevel
    threat_category: ThreatCategory
    rationale: str = Field(max_length=500)
    intent: Intent
    action: Optional[Action] = None
    execution_allowed: bool = False
    # extra fields
    signals: List[str] = Field(default_factory=list)
    candidates: List[Contact] = Field(default_factory=list)
    draft: Optional[TransferDraft] = None
    llm_status: str = "NOT_CONFIGURED"   # NOT_CONFIGURED | OK | FAILED | SKIPPED

    @model_validator(mode="after")
    def _enforce_invariants(self):
        if self.action is not None and self.decision != Decision.APPROVE:
            raise ValueError("action details must be null unless decision is APPROVE")
        if self.execution_allowed:
            if self.decision != Decision.APPROVE or self.action is None:
                raise ValueError("execution_allowed requires an approved action")
            if self.action.type == ActionType.TRANSFER:
                raise ValueError("a transfer can never be pre-authorised by analysis")
        if self.decision == Decision.APPROVE and self.threat_category != ThreatCategory.NONE:
            raise ValueError("APPROVE requires threat_category NONE")
        if self.decision == Decision.APPROVE and self.intent == Intent.TRANSFER:
            if self.action is None or self.action.type != ActionType.TRANSFER:
                raise ValueError("approved transfer must carry a TRANSFER action")
        return self


class PolicyContext(BaseModel):
    """Read-only facts the firewall needs (never contains the PIN)."""
    model_config = ConfigDict(frozen=True)
    balance: Decimal
    limit: Decimal
    contacts: Tuple[Contact, ...]

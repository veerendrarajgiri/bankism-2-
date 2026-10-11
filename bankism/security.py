"""BANKISM security firewall: validation -> normalisation -> threat detection -> policy.

Everything here is deterministic. The optional LLM can only ADD suspicion; it can never
approve something the rules blocked. No regex list can catch every attack - this is a
defence-in-depth layer, and the transaction handler re-validates everything again.
"""
import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import List, Optional

import config
from llm_analyzer import LLMSignal
from models import (Action, ActionType, Contact, Decision, Intent, PolicyContext, RiskLevel,
                    ThreatCategory as TC, TransferDraft, Verdict)
from policy import check_amount, check_memo, check_phone_number, normalize_phone_number, redact_sensitive


@dataclass(frozen=True)
class Signal:
    name: str
    category: TC
    severity: int   # 2 = suspicious (REVIEW), 3 = strong attack (BLOCK), 4 = confirmed obfuscated attack


# ------------------------------------------------------------------ detection rules
_RAW = [
    # --- prompt injection
    ("override_instructions", TC.PROMPT_INJECTION, 3,
     r"\b(?:ignore|disregard|forget|override|overrule|discard|drop)\b(?:\W+\w+){0,4}?\W+(?:instructions?|rules?|prompts?|polic(?:y|ies)|guidelines?|restrictions?|safeguards?|directives?|programming|guardrails?)\b"),
    ("new_instructions", TC.PROMPT_INJECTION, 3,
     r"\b(?:new|updated|revised|real|actual|hidden)\s+(?:system\s+)?(?:instructions?|rules?|directives?)\s*[:\-]"),
    ("system_tag", TC.PROMPT_INJECTION, 3,
     r"[\[<{]\s*/?\s*(?:system|admin|assistant|instructions?|root)\s*[\]>}]|(?:^|\n)\s*(?:system|assistant|admin)\s*:"),
    ("you_are_now", TC.PROMPT_INJECTION, 3,
     r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\b(?:\W+\w+){0,3}?\W+(?:you|ignore|act|obey)\b"),
    ("code_execution_attempt", TC.PROMPT_INJECTION, 3,
     r"\bsudo\b|\brm\s+-rf\b|\bos\.system\b|\bsubprocess\b|\beval\s*\(|\bexec\s*\(|__import__|\bimport\s+os\b"),
    # --- jailbreak / role-play
    ("jailbreak_roleplay", TC.JAILBREAK, 3,
     r"\b(?:pretend|imagine|roleplay|role-play|simulate|behave|play\s+the\s+role)\b(?:\W+\w+){0,3}?\W+(?:you\s+are|you're|youre|you\s+re|to\s+be|as|like|that\s+you)\b"),
    ("jailbreak_phrase", TC.JAILBREAK, 3,
     r"\bdo\s+anything\s+now\b|\b(?:developer|dev|god|admin|debug|maintenance|unrestricted|jailbreak|jailbroken)\s+mode\b|\b(?:no|without|free\s+of|free\s+from)\s+(?:any\s+)?(?:restrictions?|rules|filters?|safeguards?|guardrails?)\b|\bunrestricted\s+(?:ai|assistant)\b"),
    # --- impersonation (severity may be lowered later if nothing is being requested)
    ("impersonate_admin", TC.AUTHORIZATION_FAILURE, 3,
     r"\b(?:i\s+am|i'm|im|this\s+is|as|acting\s+as|speaking\s+as|on\s+behalf\s+of)\s+(?:the\s+|an?\s+|your\s+)?(?:bank\s+|system\s+|security\s+|senior\s+|head\s+|chief\s+)?(?:admin(?:istrator)?|manager|developer|root|superuser|auditor|support\s+agent|employee|ceo|engineer|officer|system)\b"),
    # --- bypass PIN / authentication / confirmation
    ("bypass_auth", TC.AUTHORIZATION_FAILURE, 3,
     r"\b(?:bypass|skip|disable|without|waive|circumvent|override|ignore|turn\s+off|switch\s+off|remove|avoid|no\s+need\s+(?:for|to)|don'?t\s+(?:ask|need|require)(?:\s+for)?|do\s+not\s+(?:ask|need|require)(?:\s+for)?|stop\s+asking(?:\s+for)?)\b(?:\W+\w+){0,3}?\W+(?:pin|passcode|otp|authenticat\w*|authori[sz]\w*|verification|verify|confirmation|confirm|2fa|mfa|password|login)\b"),
    ("claims_auth_done", TC.AUTHORIZATION_FAILURE, 2,
     r"\b(?:already|previously)[\s-]*(?:authenticated|verified|authori[sz]ed|approved|confirmed)\b|\bpin\s+(?:is\s+)?(?:already\s+)?(?:entered|verified|approved)\b|\bauto[\s-]?(?:approve|confirm|execute)\b"),
    ("credential_in_chat", TC.AUTHORIZATION_FAILURE, 2,
     r"\b(?:pin|passcode|password|otp|cvv)\b\W{0,12}(?:is\s+|=\s*)?\d{3,8}\b"),
    # --- bypass limits / security policy
    ("bypass_policy", TC.POLICY_OVERRIDE, 3,
     r"\b(?:bypass|skip|disable|waive|circumvent|override|ignore|turn\s+off|switch\s+off|remove|lift|raise|increase|exceed|unlock|disregard|get\s+around)\b(?:\W+\w+){0,3}?\W+(?:limits?|caps?|thresholds?|security|firewall|checks?|safeguards?|guardrails?|fraud|monitoring|policy|policies|restrictions?)\b"),
    # --- secrets / data exfiltration
    ("reveal_prompt", TC.DATA_EXFILTRATION, 3,
     r"\b(?:reveal|show|print|repeat|display|leak|output|tell|give|share|dump)\b(?:\W+\w+){0,3}?\W+(?:system|hidden|initial|original|secret)\s+(?:prompt|instructions?|message|rules)\b"),
    ("exfil_secret", TC.DATA_EXFILTRATION, 3,
     r"\b(?:reveal|show|tell|give|print|display|leak|repeat|share|dump|output|send|read)\b(?:\W+\w+){0,3}?\W+(?:pin|passcode|password|otp|cvv|api[\s_-]?keys?|secrets?|credentials?|tokens?|private\s+keys?|env(?:ironment)?\s+variables?)\b"),
    ("exfil_whats", TC.DATA_EXFILTRATION, 3,
     r"\bwhat(?:'s|s|\s+is|\s+are)\s+(?:my|the|your)\s+(?:\w+\s+){0,2}?(?:pin|passcode|password|otp|cvv|api[\s_-]?key|secret|credentials?)\b"),
    ("exfil_account", TC.DATA_EXFILTRATION, 3,
     r"\b(?:full|complete|entire|unmasked|actual|real)\s+(?:bank\s+)?(?:account|card)\s+(?:number|no\.?|details)\b"),
    # --- merely suspicious (REVIEW)
    ("hypothetical_framing", TC.JAILBREAK, 2,
     r"\b(?:hypothetically|for\s+(?:testing|test|debugging|research|educational)\s+purposes|just\s+a\s+test|this\s+is\s+(?:only\s+)?a\s+(?:test|drill|simulation)|in\s+a\s+(?:fictional|hypothetical)\s+(?:scenario|world))\b"),
    ("act_as", TC.JAILBREAK, 2, r"\bact\s+as\b|\bpose\s+as\b|\bplay\s+(?:a\s+)?(?:character|role)\b"),
    ("secrecy_pressure", TC.AUTHORIZATION_FAILURE, 2,
     r"\b(?:don'?t\s+tell\s+anyone|keep\s+(?:this|it)\s+secret|do\s+not\s+tell|no\s+one\s+(?:should|needs\s+to)\s+know)\b"),
]
_PATTERNS = [(n, c, s, re.compile(rx, re.I)) for n, c, s, rx in _RAW]

_TRANSFER_VERB = re.compile(r"\b(?:send|transfer(?!\s+limits?)|pay|wire|remit|donate)\b|\bmove\s+(?:money|funds|₹|\d)", re.I)
_BALANCE = re.compile(r"\b(?:balance|how\s+much\s+(?:money\s+)?(?:do\s+i\s+have|is\s+(?:in|left)|have\s+i\s+got)|funds?\s+available|available\s+funds?)\b")
_HISTORY = re.compile(r"\b(?:transactions?|history|statement|ledger|recent\s+(?:payments?|activity|transfers?)|last\s+\w+\s+(?:payments?|transfers?))\b")
_GREETING = re.compile(r"^(?:hi|hello|hey|help|thanks|thank you|good (?:morning|afternoon|evening)|what can you do)\b[\s!.?]*$")
_DISCUSSION = re.compile(r"\b(?:what\s+(?:does|do|is|are)|why\s+(?:do|does|would|is)|how\s+(?:do|does|can|would|should)|explain|meaning|means?|define|definition|examples?|phrase|attacks?|detect|prevent|protect|safe|dangerous|suspicious|learn|about)\b")
_ENCODING_CUE = re.compile(r"\b(?:rot-?13|caesar|decode|decrypt|base64|hex|reversed?|backwards?)\b", re.I)
_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

_HOMOGLYPHS = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
                              "ј": "j", "ѕ": "s", "ԁ": "d", "ο": "o", "ρ": "p", "ν": "v", "α": "a", "ε": "e",
                              "ι": "i", "κ": "k", "τ": "t"})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "i"})
_QUOTE_RX = re.compile(r"\"([^\"]{1,200})\"|(?<!\w)'([^']{1,200})'(?!\w)")

_PRIORITY = [TC.PROMPT_INJECTION, TC.JAILBREAK, TC.DATA_EXFILTRATION, TC.POLICY_OVERRIDE,
             TC.AUTHORIZATION_FAILURE, TC.OBFUSCATION]
_LABELS = {
    TC.PROMPT_INJECTION: "Prompt-injection pattern: text tries to override or replace the assistant's instructions",
    TC.JAILBREAK: "Jailbreak / malicious role-play pattern",
    TC.POLICY_OVERRIDE: "Attempt to override security policy or transfer limits",
    TC.DATA_EXFILTRATION: "Attempt to reveal secrets or confidential account data",
    TC.OBFUSCATION: "Hidden, obfuscated or encoded instructions",
    TC.AUTHORIZATION_FAILURE: "Attempt to bypass or fake PIN, authentication or confirmation",
}


# ------------------------------------------------------------------ normalisation
def _collapse(t: str) -> str:
    for a, b in (("\u2019", "'"), ("\u2018", "'"), ("\u201c", '"'), ("\u201d", '"'),
                 ("\u2212", "-"), ("\u2013", "-"), ("\u2014", "-")):
        t = t.replace(a, b)
    return re.sub(r"\s+", " ", t).strip()


def normalize_for_analysis(text: str) -> str:
    """Analysis-only view: strips invisible chars/accents, maps look-alike letters, lower-cases.
    The ORIGINAL text is kept for auditing; amounts/recipients are parsed from ASCII digits only."""
    t = unicodedata.normalize("NFKD", text)
    t = "".join(ch for ch in t if ch in "\t\n\r" or unicodedata.category(ch) not in ("Mn", "Cf", "Cc", "Cs", "Co"))
    t = t.casefold().translate(_HOMOGLYPHS)
    return _collapse(unicodedata.normalize("NFKC", t))


def _despace(t: str) -> str:
    t = re.sub(r"(?<=[a-z])[.\-_*|/\\'`~^,]+(?=[a-z])", "", t)
    return re.sub(r"\b(?:[a-z]\s){3,}[a-z]\b", lambda m: m.group(0).replace(" ", ""), t)


def split_quotes(t: str):
    quoted = [m.group(1) or m.group(2) for m in _QUOTE_RX.finditer(t)]
    return _QUOTE_RX.sub(" ", t), quoted


def _scan(text: str) -> List[Signal]:
    return [Signal(n, c, s) for n, c, s, rx in _PATTERNS if rx.search(text)]


def _script(ch: str) -> str:
    return unicodedata.name(ch, "UNKNOWN").split(" ")[0]


def _unicode_signals(text: str) -> List[Signal]:
    out = []
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn") and c not in "\n\r\t" for c in text):
        out.append(Signal("hidden_or_control_chars", TC.OBFUSCATION, 2))
    if any(c in _BIDI for c in text):
        out.append(Signal("bidi_override_chars", TC.OBFUSCATION, 3))
    if sum(1 for c in text if unicodedata.category(c) == "Mn") >= 4:
        out.append(Signal("excessive_combining_marks", TC.OBFUSCATION, 2))
    scripts = {_script(c) for c in text if c.isalpha()}
    if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
        out.append(Signal("mixed_script_lookalikes", TC.OBFUSCATION, 2))
    if any(c.isdigit() and not c.isascii() for c in text):
        out.append(Signal("non_ascii_digits", TC.OBFUSCATION, 2))
    return out


def _mostly_text(s: str) -> bool:
    return len(s) >= 6 and s.isprintable() and sum(c.isalpha() or c.isspace() for c in s) / len(s) >= 0.8


def _decoded_variants(text: str):
    """Return (variants_found, rot_or_reverse_variants)."""
    found, extra = [], []
    for tok in re.findall(r"[A-Za-z0-9+/_-]{16,}={0,2}", text):
        std = tok.rstrip("=").replace("-", "+").replace("_", "/")
        std += "=" * (-len(std) % 4)
        try:
            s = base64.b64decode(std, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _mostly_text(s):
            found.append(s)
    for tok in re.findall(r"(?:0x)?((?:[0-9a-fA-F]{2}){8,})", text):
        try:
            s = bytes.fromhex(tok).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _mostly_text(s):
            found.append(s)
    if re.search(r"(?:%[0-9a-fA-F]{2}.*){3,}", text):
        found.append(urllib.parse.unquote(text))
    if re.search(r"(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){3,}", text):
        found.append(re.sub(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})",
                            lambda m: chr(int(m.group(1) or m.group(2), 16)), text))
    if _ENCODING_CUE.search(text):
        extra += [codecs.decode(text, "rot_13"), text[::-1]]
    return found, extra


@dataclass
class ThreatScan:
    unq: str
    quoted: List[str]
    unq_signals: List[Signal]
    quoted_signals: List[Signal]


def _threat_scan(text: str) -> ThreatScan:
    raw_names = {s.name for s in _scan(_collapse(unicodedata.normalize("NFC", text).casefold()))}
    norm = normalize_for_analysis(text)
    unq, quoted = split_quotes(norm)

    def reveal(sigs):   # strong signal that ONLY appears after normalisation => obfuscated attack
        return [Signal("obfuscated_" + s.name, TC.OBFUSCATION, 4) if s.severity >= 3 and s.name not in raw_names else s
                for s in sigs]

    unq_sigs = reveal(_scan(unq))
    q_sigs = reveal([s for q in quoted for s in _scan(q)])
    known = {s.name for s in unq_sigs} | raw_names
    for view in (_despace(unq), unq.translate(_LEET), _despace(unq.translate(_LEET))):
        if any(s.severity >= 3 and s.name not in known for s in _scan(view)):
            unq_sigs.append(Signal("obfuscated_text", TC.OBFUSCATION, 4))
            break
    unq_sigs += _unicode_signals(text)
    found, extra = _decoded_variants(text)
    if any(s.severity >= 3 for v in found + extra for s in _scan(normalize_for_analysis(v))):
        unq_sigs.append(Signal("encoded_attack", TC.OBFUSCATION, 4))
    elif found:
        unq_sigs.append(Signal("encoded_content", TC.OBFUSCATION, 2))
    return ThreatScan(unq, quoted, unq_sigs, q_sigs)


# ------------------------------------------------------------------ intent & transfer parsing
def _classify_intent(unq: str) -> Intent:
    if _TRANSFER_VERB.search(unq):
        return Intent.TRANSFER
    if _BALANCE.search(unq):
        return Intent.BALANCE_INQUIRY
    if _HISTORY.search(unq):
        return Intent.TRANSACTION_HISTORY
    return Intent.UNKNOWN


_NUMWORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}


def _history_count(unq: str) -> int:
    m = re.search(r"\b(?:last|recent|latest|past|previous|top)\s+(\w+)", unq)
    n = config.HISTORY_DEFAULT_COUNT
    if m:
        w = m.group(1)
        n = int(w) if w.isdigit() else _NUMWORDS.get(w, n)
    return max(1, min(n, config.HISTORY_MAX_COUNT))


_MEMO_KW = re.compile(r"\b(?:for|memo|note|remarks?|reference|reason|description|saying|message|label(?:l?ed)?)\b\s*[:\-]?\s*")
_MEMO_CUE = re.compile(r"\b(?:memo|note|remarks?|reference|description|message|saying|label)\b")
_TO_RX = re.compile(r"\bto\s+(.+?)(?=\s+(?:for|with|and|then|because|as|memo|note|from|via|using|please|now|today|tomorrow|asap|by|on|at)\b|[,.;:!?]|$)")
_FILLER = {"my", "friend", "mr", "mrs", "ms", "dr", "the", "dear", "bro", "buddy", "mate", "contact", "account",
           "a", "an", "saved", "our", "pal", "sir", "madam"}
_FOREIGN = re.compile(r"[$€£¥]|\b(?:usd|eur|gbp|dollars?|euros?|pounds?|yen|aed|bitcoin|btc|eth|crypto)\b")
_BADNUM = re.compile(r"\b\d+(?:\.\d+)?e[+-]?\d+\b|\bnan\b|\binfinit(?:y|e)\b|\binf\b")
_SUFFIX = re.compile(r"\d\s*(?:k|lakhs?|lacs?|crores?|cr|million|thousand|hundred|mn)\b")
_NUM_RX = re.compile(r"(?<![\w.])-?\d[\d,]*(?:\.\d+)?(?![\w])")


@dataclass
class _Parsed:
    amount_state: str            # OK | MISSING | MULTIPLE | SUFFIX | INVALID | FOREIGN
    amount: Optional[Decimal]
    recipient_state: str         # OK | MISSING | AMBIGUOUS | UNKNOWN | PHONE | INVALID_PHONE
    matches: List[Contact]
    memo: str
    amount_msg: str = ""
    phone: Optional[str] = None
    phone_msg: str = ""


def _tokens(c: Contact):
    return set(re.findall(r"[a-z]+", c.name.casefold())) | {c.id.casefold()}


def _resolve(tokens, contacts):
    exact = [c for c in contacts if all(t in _tokens(c) for t in tokens)]
    if exact:
        return exact
    return [c for c in contacts if all(any(n.startswith(t) for n in _tokens(c)) for t in tokens)]


def _clean_memo(t: str) -> str:
    t = re.sub(r"\s+", " ", t).strip(" .,;:!?-\"'")
    return (t[:1].upper() + t[1:]) if t else ""


def _parse_amount(t: str):
    if _FOREIGN.search(t):
        return "FOREIGN", None, "Only INR (₹) transfers are supported in this demo."
    if _BADNUM.search(t):
        return "INVALID", None, "Amount must be a plain, finite number."
    if _SUFFIX.search(t):
        return "SUFFIX", None, "Please write the full numeric amount (for example 5000, not 5k)."
    t = re.sub(r"\b(?:minus|negative)\s+", "-", t)
    t = re.sub(r"\b(?:rs\.?|inr)\s*(?=[\d-])|₹\s*", " ", t)
    t = re.sub(r"(?<=\d)\s*(?:rs|inr|rupees?)\b", " ", t)
    nums = _NUM_RX.findall(t)
    values = set()
    for n in nums:
        try:
            values.add(Decimal(n.replace(",", "")))
        except InvalidOperation:
            return "INVALID", None, "Amount must be a plain, finite number."
    if not values:
        return "MISSING", None, ""
    if len(values) > 1:
        return "MULTIPLE", None, "I found more than one amount."
    return "OK", values.pop(), ""


def _parse_transfer(unq: str, quoted: List[str], contacts) -> _Parsed:
    mk = _MEMO_KW.search(unq)
    region = unq[:mk.start()] if mk else unq
    rm = _TO_RX.search(region) or (_TO_RX.search(unq) if mk else None)
    memo_text = ""
    if mk:
        memo_text = unq[mk.end():]
        if rm is not None and rm.start() >= mk.end():
            memo_text = unq[mk.end():rm.start()] + " " + unq[rm.end():]
    if quoted and (_MEMO_CUE.search(unq) or not memo_text.strip(" .,;:!?")):
        memo_text = quoted[0]
    memo = _clean_memo(memo_text)

    phone_candidate = None
    phone_msg = ""
    if rm is not None:
        target = rm.group(1).strip()
        phone_match = re.search(r"\+?\d[\d\s\-()]{8,}\d|\b\d{10}\b", target)
        if phone_match or (any(c.isdigit() for c in target) and not re.search(r"[a-zA-Z]", target)):
            cand = phone_match.group(0) if phone_match else target
            phone_err = check_phone_number(cand)
            if phone_err:
                state = "INVALID_PHONE"
                phone_msg = phone_err[1]
                matches = []
            else:
                norm = normalize_phone_number(cand)
                saved = next((c for c in contacts if getattr(c, "phone", None) and
                              re.sub(r"\D", "", c.phone) == re.sub(r"\D", "", norm)), None)
                if saved:
                    matches = [saved]
                    state = "OK"
                else:
                    state = "PHONE"
                    phone_candidate = norm
                    matches = []
        else:
            toks = [t for t in re.findall(r"[a-z0-9]+", target) if not t.isdigit() and t not in _FILLER]
            matches = _resolve(toks, contacts) if toks else []
            state = "MISSING" if not toks else "UNKNOWN" if not matches else "OK" if len(matches) == 1 else "AMBIGUOUS"
    else:
        words = set(re.findall(r"[a-z0-9]+", region))
        matches = [c for c in contacts if any(t in words for t in _tokens(c) if len(t) >= 3)]
        state = "MISSING" if not matches else "OK" if len(matches) == 1 else "AMBIGUOUS"

    amount_text = region
    if rm is not None and rm.start() < len(region):
        amount_text = region[:rm.start()] + " " + region[rm.end():]
    if phone_candidate:
        amount_text = re.sub(r"\+?\d[\d\s\-()]{8,}\d", " ", amount_text)
    a_state, amount, msg = _parse_amount(amount_text)
    return _Parsed(a_state, amount, state, matches, memo, msg, phone=phone_candidate, phone_msg=phone_msg)


# ------------------------------------------------------------------ verdict helpers
def _verdict(decision, risk, cat, rationale, intent, action=None, allowed=False, **kw) -> Verdict:
    return Verdict(decision=decision, risk_level=risk, threat_category=cat, rationale=rationale,
                   intent=intent, action=action, execution_allowed=allowed, **kw)


def _top_category(sigs: List[Signal]) -> TC:
    best = max(sigs, key=lambda s: (s.severity, -_PRIORITY.index(s.category) if s.category in _PRIORITY else -99))
    return best.category


def _threat_verdict(sigs, intent, transfer_verb, memo_attack, llm_status="NOT_CONFIGURED") -> Optional[Verdict]:
    names = sorted({s.name for s in sigs})
    strong = [s for s in sigs if s.severity >= 3]
    if strong:
        cat = _top_category(strong)
        label = ("Malicious instruction hidden in a payment memo or quoted text"
                 if memo_attack else _LABELS.get(cat, "Attack pattern detected"))
        risk = RiskLevel.CRITICAL if (transfer_verb or any(s.severity >= 4 for s in strong)) else RiskLevel.HIGH
        return _verdict(Decision.BLOCK, risk, cat, f"{label}. Blocked by the deterministic firewall; no banking action was taken.",
                        intent, signals=names)
    medium = [s for s in sigs if s.severity == 2]
    if medium:
        cat = _top_category(medium)
        if any(s.name == "credential_in_chat" for s in medium):
            why = "A PIN-like secret was typed into chat. Never share a PIN in chat; it is only entered in the confirmation form"
        else:
            why = "Suspicious but not conclusive: " + _LABELS.get(cat, "unusual input").lower()
        return _verdict(Decision.REVIEW, RiskLevel.MEDIUM, cat, f"{why}. Held for review; no banking action was taken.",
                        intent, signals=names)
    return None


def _adjust_impersonation(sigs, transfer_verb):
    others = any(s.severity >= 3 and s.name != "impersonate_admin" for s in sigs)
    if any(s.name == "impersonate_admin" for s in sigs) and not others and not transfer_verb:
        return [Signal(s.name, s.category, 2) if s.name == "impersonate_admin" else s for s in sigs]
    return sigs


def _bad_amount_verdict(msg, code) -> Verdict:
    return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_TRANSACTION, f"Invalid or out-of-policy amount: {msg}",
                    Intent.TRANSFER, signals=[code.lower()])


def _final_transfer_checks(amount, memo, contact: Optional[Contact], ctx,
                           recipient_phone: Optional[str] = None, recipient_name: Optional[str] = None) -> Verdict:
    err = check_amount(amount, ctx.limit, ctx.balance)
    if err:
        return _bad_amount_verdict(err[1], err[0])
    merr = check_memo(memo)
    if merr:
        return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_TRANSACTION, merr, Intent.TRANSFER, signals=["invalid_memo"])
    cid = contact.id if contact else None
    phone = recipient_phone or (getattr(contact, "phone", None) if contact else None)
    cname = contact.name if contact else (recipient_name or phone)
    action = Action(type=ActionType.TRANSFER, contact_id=cid, contact_name=cname,
                    recipient_phone=phone, amount=amount, currency=config.CURRENCY, memo=memo or "Transfer")
    return _verdict(Decision.APPROVE, RiskLevel.LOW, TC.NONE,
                    "Request passed analysis. This does NOT authorise a transfer: exact confirmation and the demo PIN are still required.",
                    Intent.TRANSFER, action=action, allowed=False)


def _evaluate_transfer(p: _Parsed, ctx: PolicyContext) -> Verdict:
    if p.amount_state in ("FOREIGN", "INVALID"):
        return _bad_amount_verdict(p.amount_msg, p.amount_state)
    if p.amount_state == "OK":
        err = check_amount(p.amount, ctx.limit, ctx.balance)
        if err:
            return _bad_amount_verdict(err[1], err[0])
    if p.recipient_state == "INVALID_PHONE":
        return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_TRANSACTION,
                        f"Invalid phone number: {p.phone_msg}",
                        Intent.TRANSFER, signals=["invalid_phone"])
    if p.recipient_state == "UNKNOWN":
        return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_TRANSACTION,
                        "Unknown recipient: the name does not match any saved contact. Only saved contacts can receive transfers.",
                        Intent.TRANSFER, signals=["unknown_recipient"])
    problems, candidates = [], []
    if p.recipient_state == "MISSING":
        problems.append("who should receive the money")
        candidates = list(ctx.contacts)
    elif p.recipient_state == "AMBIGUOUS":
        problems.append("which contact you mean (several saved contacts match)")
        candidates = p.matches
    if p.amount_state != "OK":
        problems.append(p.amount_msg.rstrip(".") + ". Please give the amount" if p.amount_msg else "the amount")
    if problems:
        draft = TransferDraft(amount=p.amount if p.amount_state == "OK" else None, memo=p.memo)
        return _verdict(Decision.CLARIFICATION_REQUIRED, RiskLevel.LOW, TC.AMBIGUOUS_REQUEST,
                        "I need to know " + " and ".join(problems) + " before I can prepare this transfer.",
                        Intent.TRANSFER, signals=["incomplete_transfer"], candidates=candidates, draft=draft)
    if p.recipient_state == "PHONE":
        return _final_transfer_checks(p.amount, p.memo, None, ctx, recipient_phone=p.phone)
    return _final_transfer_checks(p.amount, p.memo, p.matches[0], ctx)


# ------------------------------------------------------------------ optional LLM signal
def _apply_llm(v: Verdict, text: str, llm) -> Verdict:
    if llm is None:
        return v
    if v.decision == Decision.BLOCK:       # a deterministic block is final; do not even ask
        return v.model_copy(update={"llm_status": "SKIPPED"})
    try:
        signal = llm.analyze(redact_sensitive(text))
        if not isinstance(signal, LLMSignal):
            raise ValueError("malformed LLM output")
    except Exception:  # timeout, network, malformed output...
        if v.intent == Intent.TRANSFER and v.decision == Decision.APPROVE:
            return _verdict(Decision.REVIEW, RiskLevel.MEDIUM, TC.ANALYSIS_FAILURE,
                            "The optional LLM analysis failed or returned malformed output, so this financial request fails closed.",
                            Intent.TRANSFER, signals=v.signals + ["llm_failure"], llm_status="FAILED")
        return v.model_copy(update={"llm_status": "FAILED"})
    if signal.is_attack and signal.confidence >= 0.5:
        cat = signal.category if signal.category != TC.NONE else TC.PROMPT_INJECTION
        if signal.confidence >= 0.85:
            return _verdict(Decision.BLOCK, RiskLevel.HIGH, cat,
                            "A second-opinion LLM flagged this request as a likely attack with high confidence. Blocked; no banking action was taken.",
                            v.intent, signals=v.signals + ["llm_flagged"], llm_status="OK")
        if v.decision == Decision.APPROVE:
            return _verdict(Decision.REVIEW, RiskLevel.MEDIUM, cat,
                            "A second-opinion LLM flagged this request as possibly malicious. Held for review; no banking action was taken.",
                            v.intent, signals=v.signals + ["llm_flagged"], llm_status="OK")
    return v.model_copy(update={"llm_status": "OK"})


# ------------------------------------------------------------------ public entry points
def _analyze(text, ctx: PolicyContext) -> Verdict:
    if not isinstance(text, str):
        return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_INPUT, "Input must be plain text.", Intent.UNKNOWN)
    if not text.strip():
        return _verdict(Decision.CLARIFICATION_REQUIRED, RiskLevel.LOW, TC.AMBIGUOUS_REQUEST,
                        "The message is empty. Ask about your balance, history, or a transfer.", Intent.UNKNOWN)
    if len(text) > config.MAX_INPUT_LENGTH:
        return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_INPUT,
                        f"Message is too long (max {config.MAX_INPUT_LENGTH} characters).", Intent.UNKNOWN)

    scan = _threat_scan(text)
    unq = scan.unq
    transfer_verb = bool(_TRANSFER_VERB.search(unq))
    intent = _classify_intent(unq)
    sigs = list(scan.unq_signals)
    memo_attack = discussion = False

    q_strong = [s for s in scan.quoted_signals if s.severity >= 3]
    if q_strong:
        if transfer_verb:                         # quoted text inside a payment request = memo
            sigs += q_strong
            memo_attack = True
        elif _DISCUSSION.search(unq):             # quoting a phrase to ask about it is not an attack
            discussion = True
        else:
            sigs.append(Signal("quoted_suspicious_phrase", q_strong[0].category, 2))
    parsed = None
    if transfer_verb:
        parsed = _parse_transfer(unq, scan.quoted, ctx.contacts)
        if any(s.severity >= 3 for s in _scan(parsed.memo.lower())):
            memo_attack = True
    request_cue = transfer_verb or bool(re.search(r"\d|\bpayments?\b|\bauthori[sz]e", unq))
    sigs = _adjust_impersonation(sigs, request_cue)

    threat = _threat_verdict(sigs, intent, transfer_verb, memo_attack)
    if threat:
        return threat

    if intent == Intent.BALANCE_INQUIRY:
        return _verdict(Decision.APPROVE, RiskLevel.LOW, TC.NONE, "Read-only balance inquiry passed all checks.", intent,
                        action=Action(type=ActionType.BALANCE_INQUIRY), allowed=True)
    if intent == Intent.TRANSACTION_HISTORY:
        return _verdict(Decision.APPROVE, RiskLevel.LOW, TC.NONE, "Read-only history request passed all checks.", intent,
                        action=Action(type=ActionType.TRANSACTION_HISTORY, count=_history_count(unq)), allowed=True)
    if intent == Intent.TRANSFER:
        return _evaluate_transfer(parsed, ctx)
    if discussion:
        return _verdict(Decision.APPROVE, RiskLevel.LOW, TC.NONE,
                        "Educational mention of a suspicious phrase. Quoted text is treated as data, not as an instruction; nothing was executed.",
                        Intent.UNKNOWN, signals=["quoted_phrase_discussed"])
    if _GREETING.match(unq):
        return _verdict(Decision.APPROVE, RiskLevel.LOW, TC.NONE, "Greeting or help request; no banking action involved.", Intent.UNKNOWN)
    return _verdict(Decision.CLARIFICATION_REQUIRED, RiskLevel.LOW, TC.AMBIGUOUS_REQUEST,
                    "I could not tell what you want. I can show your balance, show recent transactions, or prepare a transfer.",
                    Intent.UNKNOWN)


def _failed_closed(exc: Exception) -> Verdict:
    return _verdict(Decision.BLOCK, RiskLevel.HIGH, TC.ANALYSIS_FAILURE,
                    "The security analysis failed unexpectedly, so the request was blocked (fail closed).",
                    Intent.UNKNOWN, signals=["analysis_exception"])


def analyze_request(text, ctx: PolicyContext, llm=None) -> Verdict:
    """Analyse one free-text request. Never raises; never executes anything."""
    try:
        verdict = _analyze(text, ctx)
        return _apply_llm(verdict, text, llm) if isinstance(text, str) else verdict
    except Exception as exc:  # fail closed
        return _failed_closed(exc)


def analyze_transfer_form(contact_id, amount, memo, ctx: PolicyContext, llm=None,
                          recipient_phone: Optional[str] = None, recipient_name: Optional[str] = None) -> Verdict:
    """Analyse a structured transfer (form or clarification click). The memo is untrusted text."""
    try:
        memo = "" if memo is None else memo
        if not isinstance(memo, str):
            return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_INPUT, "Memo must be text.", Intent.TRANSFER)
        if len(memo) > config.MAX_INPUT_LENGTH:
            return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_INPUT, "Memo is too long.", Intent.TRANSFER)
        scan = _threat_scan(memo)
        threat = _threat_verdict(scan.unq_signals + scan.quoted_signals, Intent.TRANSFER, True, True)
        if threat:
            return threat

        contact = None
        if contact_id is not None:
            contact = next((c for c in ctx.contacts if c.id == contact_id), None)
            if contact is None:
                return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_TRANSACTION,
                                "Unknown recipient: only saved contacts or valid phone numbers can receive transfers.",
                                Intent.TRANSFER, signals=["unknown_recipient"])
            recipient_phone = recipient_phone or getattr(contact, "phone", None)
            recipient_name = contact.name

        if contact is None:
            if not recipient_phone or not str(recipient_phone).strip():
                return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_TRANSACTION,
                                "Recipient phone number is required.", Intent.TRANSFER,
                                signals=["missing_phone"])
            phone_err = check_phone_number(str(recipient_phone).strip())
            if phone_err:
                return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_TRANSACTION,
                                phone_err[1], Intent.TRANSFER, signals=[phone_err[0].lower()])
            recipient_phone = normalize_phone_number(str(recipient_phone).strip())
            if recipient_name:
                recipient_name = str(recipient_name).strip()
                if len(recipient_name) > 60:
                    return _verdict(Decision.BLOCK, RiskLevel.MEDIUM, TC.INVALID_INPUT,
                                    "Recipient name is too long.", Intent.TRANSFER, signals=["invalid_name"])
                name_scan = _threat_scan(recipient_name)
                name_threat = _threat_verdict(name_scan.unq_signals + name_scan.quoted_signals, Intent.TRANSFER, True, False)
                if name_threat:
                    return name_threat

        if amount is None:
            display_target = contact.name if contact else (recipient_name or recipient_phone)
            return _verdict(Decision.CLARIFICATION_REQUIRED, RiskLevel.LOW, TC.AMBIGUOUS_REQUEST,
                            f"How much would you like to send to {display_target}? Please type the amount.", Intent.TRANSFER,
                            signals=["incomplete_transfer"], draft=TransferDraft(memo=memo))
        if not isinstance(amount, Decimal):
            try:
                amount = Decimal(str(amount))
            except InvalidOperation:
                return _bad_amount_verdict("Amount must be a number.", "INVALID_AMOUNT")
        verdict = _final_transfer_checks(amount, memo.strip(), contact, ctx,
                                         recipient_phone=recipient_phone, recipient_name=recipient_name)
        return _apply_llm(verdict, f"transfer memo: {memo}", llm)
    except Exception as exc:  # fail closed
        return _failed_closed(exc)

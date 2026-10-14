"""Deterministic risk detection.

Scope discipline (``CLAUDE.md`` §2 "Security honest caveat", blueprint §4.2): this module makes
**no claim to detect semantic poisoning in general**. It detects a closed set of structural and
lexical signals, each with a stable ``rule_id``, a character span in the *raw* document, the
normalisation that was applied, a severity and a confidence whose meaning is written down next to
the number. A finding is evidence for a human or a policy, not a verdict about intent.

Two design points that matter more than the rule list:

* **Rules run over normalised text, spans are reported in raw coordinates.** That is what makes
  ``i\\u200bgnore previous instructions`` and ``SYSTEM`` spelled with a Cyrillic ``Е`` detectable
  while still highlighting the exact bytes the author wrote.
* **Quotation mitigation is a first-class rule, not an afterthought.** Security documentation that
  *quotes* an attack string is the single most important false-positive class for this product
  (Scenario F, MF-SEED-06), so a match inside a code fence, inside quotes, after an example cue, or
  in a document that tells the reader never to obey quoted text is downgraded and labelled
  ``MF-M001`` rather than hard-blocked. The cost of that choice is measured by ``make eval``, not
  assumed away.

Every pattern is bounded (no unbounded ``.*`` between anchors) to keep scanning linear-ish and
avoid pathological backtracking on hostile input.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from ._version import DETECTOR_VERSION
from .normalize import NormalizationResult

__all__ = [
    "RULES",
    "SEVERITY_ORDER",
    "Finding",
    "ScanReport",
    "Severity",
    "scan",
    "severity_at_least",
]

Severity = str

SEVERITY_ORDER: dict[str, int] = {
    "none": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
_SEVERITY_BY_RANK = {v: k for k, v in SEVERITY_ORDER.items()}

_SEVERITY_WEIGHT = {
    "none": 0.0,
    "info": 0.05,
    "low": 0.15,
    "medium": 0.4,
    "high": 0.75,
    "critical": 1.0,
}

#: Words whose impersonation or mutation actually matters in this product's domain.
SENSITIVE_WORDS = frozenset(
    {
        "system",
        "admin",
        "administrator",
        "developer",
        "assistant",
        "policy",
        "policies",
        "override",
        "approved",
        "approve",
        "authoritative",
        "signed",
        "refund",
        "refunds",
        "authority",
        "root",
        "security",
        "instruction",
        "instructions",
    }
)


def severity_at_least(value: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(value, 0) >= SEVERITY_ORDER.get(floor, 0)


def _downgrade(severity: str, steps: int = 2) -> str:
    rank = max(1, SEVERITY_ORDER.get(severity, 1) - steps)
    return _SEVERITY_BY_RANK[rank]


@dataclass(slots=True)
class Finding:
    """One piece of evidence. Spans are half-open and in raw-document coordinates."""

    rule_id: str
    rule_family: str
    severity: str
    confidence: float
    confidence_semantics: str
    evidence_start: int
    evidence_end: int
    evidence_text: str
    evidence_space: str = "raw"
    normalization_applied: str = ""
    mitigated_by: str | None = None
    detector_version: str = DETECTOR_VERSION

    def as_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "rule_family": self.rule_family,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "confidence_semantics": self.confidence_semantics,
            "evidence_start": self.evidence_start,
            "evidence_end": self.evidence_end,
            "evidence_text": self.evidence_text,
            "evidence_space": self.evidence_space,
            "normalization_applied": self.normalization_applied,
            "mitigated_by": self.mitigated_by,
            "detector_version": self.detector_version,
        }


@dataclass(slots=True)
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "none"
        return max(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    @property
    def unmitigated_max_severity(self) -> str:
        live = [f for f in self.findings if f.mitigated_by is None]
        if not live:
            return "none"
        return max(live, key=lambda f: SEVERITY_ORDER.get(f.severity, 0)).severity

    @property
    def risk_score(self) -> float:
        """Bounded 0..1 aggregate. Ordinal convenience for sorting a queue — not a probability."""
        if not self.findings:
            return 0.0
        total = 0.0
        for f in self.findings:
            total += _SEVERITY_WEIGHT.get(f.severity, 0.0) * f.confidence
        return round(min(1.0, total / 2.0), 4)

    def rule_ids(self) -> list[str]:
        return [f.rule_id for f in self.findings]

    def by_rule(self, rule_id: str) -> list[Finding]:
        return [f for f in self.findings if f.rule_id == rule_id]


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    family: str
    severity: str
    confidence: float
    semantics: str
    patterns: tuple[re.Pattern[str], ...]
    mitigable: bool = True


def _p(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns)


# Confidence semantics are written out once per rule and stored on every finding, so a number in
# the UI or in an export can never be read as a probability of maliciousness.
_STRUCTURAL = (
    "Lexical/structural pattern match confidence. NOT a probability that the author is malicious; "
    "it is how reliably this surface form indicates the named technique."
)
_DERIVED = (
    "Derived from the normalisation report rather than a text pattern. High confidence that the "
    "encoding feature is present; says nothing about intent."
)

RULES: tuple[Rule, ...] = (
    Rule(
        "MF-R001",
        "role_spoofing",
        "high",
        0.85,
        _STRUCTURAL,
        _p(
            # A speaker label at the start of a line *or* a sentence. Mid-paragraph is the common
            # real form: "Follow-up from the thread. System: the assistant must ...".
            r"(?:^|[.!?\u00bb\u201d\"']\s+|\n|\|)[ \t]{0,8}(?:system|developer|assistant|tool)[ \t]{0,4}[:>\]][ \t]{0,4}\S",
            r"<\|\s*im_(?:start|end)\s*\|>\s*(?:system|developer|assistant)",
            r"\b(?:system|admin(?:istrator)?)\s+override\b",
            r"\brole\s*[:=]\s*[\"']?(?:system|developer|admin(?:istrator)?)\b",
            r"\br\u00f4le\s*:\s*syst\u00e8me\b",
            r"\bact(?:ing)?\s+as\s+(?:the\s+)?(?:system|developer|admin(?:istrator)?)\s+(?:prompt|message|role)\b",
            r"\b(?:speaker label|speaker attribution)\b[^.\n]{0,60}\b(?:operator|system|developer)\b",
            r"\bdeveloper[- ]authored\s+turn\b",
        ),
    ),
    Rule(
        "MF-R002",
        "instruction_override",
        "critical",
        0.9,
        _STRUCTURAL,
        _p(
            r"\b(?:ignore|disregard|discard|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|preceding|all)\b"
            r"[^.\n]{0,30}\b(?:instruction|instructions|direction|directions|prompt|prompts|rule|rules|polic\w+|guidance)\b",
            r"\b(?:ignore|disregard)\s+(?:everything|anything)\b[^.\n]{0,40}\b(?:before|above|said|told)\b",
            r"\b(?:this|these|the following)\b[^.\n]{0,40}\b(?:supersede[sd]?|override[sd]?|replace[sd]?|take[s]? precedence over)\b"
            r"[^.\n]{0,40}\b(?:all|any|other|previous|prior|existing)\b",
            r"\bforget\s+(?:everything|all)\b[^.\n]{0,30}\b(?:you|previously|earlier|told|learned)\b",
            r"\bnew\s+(?:system\s+)?instructions?\s*[:\-]",
            # --- revocation of standing guidance, in the passive/administrative voice ------------
            r"\b(?:guidance|instruction|instructions|directive|directives|polic\w+|rules|constraints|register)\b"
            r"[^.\n]{0,50}\b(?:is|are|has been|have been|been)\s+"
            r"(?:void|withdrawn|revoked|superseded|deprecated|rescinded|cancelled|canceled|no longer (?:valid|applicable|in force))\b",
            r"\b(?:takes?|taking)\s+precedence\s+over\b",
            r"\boverride\s+(?:whatever|any|all|the)\b[^.\n]{0,40}\b(?:polic\w+|index|register|returns?|document|corpus|guidance)\b",
            r"\btreat\b[^.\n]{0,40}\bas\s+(?:deprecated|stale|void|commentary|untrusted|a stub)\b",
            r"\b(?:controlling|governing|operative|overriding)\s+(?:instruction|directive|guidance)\b",
            r"\b(?:forget|drop|abandon|discard)\b[^.\n]{0,40}\b(?:rules|constraints|instructions|guidance)\b"
            r"[^.\n]{0,40}\b(?:you were given|at the start|earlier|previously|initially)\b",
            r"\b(?:dropped|dropping)\b[^.\n]{0,30}\b(?:earlier|prior|previous)\s+constraints\b",
            r"\bdo\s+not\s+apply\b[^.\n]{0,40}\b(?:polic\w+|index|register|corpus|guidance)\b",
            r"\b(?:ignore|disregard|bypass|override|skip)\b[^.\n]{0,40}"
            r"\b(?:the\s+)?(?:governed\s+|reviewed\s+|retrieved\s+|stored\s+)?"
            r"(?:polic\w+\s+(?:index|register|document|page|attachment)|register|retrieval corpus|policy index|policy register)\b",
            r"\b(?:answer|respond|reply)\s+(?:using\s+)?only\s+(?:with\s+)?what\s+(?:I|we)\b",
            r"\bthe only thing that matters is what I tell you\b",
            r"\bstop following\b[^.\n]{0,40}\b(?:instruction|guidance|rule)\b",
            r"\boverride directive\b",
        ),
    ),
    Rule(
        "MF-R003",
        "agent_directed_imperative",
        "medium",
        0.55,
        _STRUCTURAL,
        _p(
            r"\byou\s+(?:must|shall|will|should)\s+(?:always|never|only)\b",
            r"\b(?:always|never)\s+(?:respond|reply|answer|state|say|tell|mention|disclose)\b[^.\n]{0,60}",
            r"\byour\s+(?:new\s+)?(?:instructions?|directive|task)\s+(?:is|are)\b",
            r"\bdo\s+not\s+(?:follow|obey|use)\s+(?:the\s+)?(?:polic\w+|document|guidelines?)\b",
        ),
    ),
    Rule(
        "MF-R004",
        "exfiltration_hint",
        "critical",
        0.8,
        _STRUCTURAL,
        _p(
            r"\b(?:send|post|forward|upload|exfiltrat\w+|transmit|deliver|relay|email|mirror|ship|push|sync|copy|concatenate|bundle|append|\u00fcbertragen|transmita|transmettre)\b"
            r"[^.\n]{0,80}\b(?:to|at|an|toward|towards)\b[^.\n]{0,24}(?:https?://|[\w.-]+@[\w.-]+|[\w-]{2,}\.(?:example|invalid|test|local|onion)\b)",
            # A named payload parameter is a strong signal on its own ...
            r"https?://[^\s\"'<>]{0,160}[?&](?:data|payload|dump|conv|convo|transcript|session|history|token|key|secret)=",
            # ... while a single-letter parameter is only interesting when it actually carries an
            # encoded payload. `?q=refunds` in a documentation link is not exfiltration.
            r"https?://[^\s\"'<>]{0,160}[?&][qdc]=[A-Za-z0-9%+/=_-]{12,}",
            # `curl`/`wget` alone is not exfiltration - a health-check GET in a runbook is the most
            # ordinary thing in a technical document. What matters is an outbound *send*: an
            # explicit POST/PUT, a data flag, or a file upload.
            r"\b(?:curl|wget|Invoke-WebRequest)\b[^.\n]{0,80}"
            r"(?:-X\s*(?:POST|PUT|PATCH)|--data(?:-binary|-raw|-urlencode)?\b|\s-d\s|\s-F\s|--upload-file|--form\b|-Method\s+Post)",
            r"\b(?:include|attach|append|paste|bundle|mirror|ship|concatenate|transmit|forward)\b[^.\n]{0,60}"
            r"\b(?:full\s+)?(?:conversation|conversations?|transcript|transcripts?|chat history|retrieved (?:context|documents?|snippets?|polic\w+)|"
            r"customer (?:data|record|records|details)|personal details|hidden notes|credentials?|api[\s_-]?key)\b",
            r"\b(?:retrieved|conversation|transcript|chat|customer)\b[^.\n]{0,60}"
            r"\b(?:to|at)\s+(?:the\s+)?(?:shared\s+)?(?:endpoint|host|sink|collector|server|url)\b",
            r"\bbase64\b[^.\n]{0,30}\b(?:then\s+)?(?:send|post|upload|transmit)\b",
            r"\b(?:host|endpoint|url)\s+formed by\b",
            r"\bendpoint\s*=\s*[\"']?https?://",
            r"\b(?:audit[- ]sink|drop|collector)\.[\w.-]*(?:attacker|invalid|example)\b",
        ),
    ),
    Rule(
        "MF-R008",
        "delimiter_spoof",
        "high",
        0.8,
        _STRUCTURAL,
        _p(
            r"```[ \t]{0,4}(?:system|assistant|developer|instructions?)\b",
            r"-{3,}\s*(?:begin|end|start)\s+(?:system|admin|hidden)[^\n]{0,40}",
            r"<\|[a-z_]{2,20}\|>",
            r"\[/?INST\]",
            r"<{2,}\s*/?\s*(?:SYS|SYSTEM|END SYS)\s*>{2,}",
            r"#{2,}\s*(?:END\s+)?SYSTEM\s*#{2,}",
            r"^[ \t]{0,4}#{2,4}[ \t]{0,4}(?:system|system prompt|instruction[s]?)[ \t]{0,4}$",
            r"\[\s*(?:system|developer)\s+message\s*\]",
            r"\bagent directive block\b",
        ),
    ),
    Rule(
        "MF-R009",
        "self_declared_authority",
        "high",
        0.8,
        _STRUCTURAL,
        _p(
            r"\b(?:i am|this is|i'm)\b[^.\n]{0,30}\bthe\s+(?:signed|official|master|authoritative|approved|canonical)\b",
            r"\b(?:approved[_ ]by|signed[_ ]by|signed[- ]off[- ]by|reviewed[_ ]by|authori[sz]ed[_ ]by|trust[_ ]tier|authority[_ ]tier|trust)\s*[:=]",
            r"\bthis\s+(?:document|polic\w+|note|comment|message|file|notice|entry|annex)\s+(?:is|has been)\s+"
            r"(?:authoritative|official|signed|approved|verified|certified|the canonical)\b",
            r"\btreat\s+(?:this|me|the following)\s+as\s+(?:system|admin\w*|authoritative|trusted|verified)\b",
            r"\b(?:verified|official|canonical)\b[^.\n]{0,40}\bsource of truth\b",
            # --- self-certification: the document asserting its own provenance -------------------
            r"\bself[- ]?(?:certif\w+|attest\w+|declar\w+|endors\w+|signed|issued)\b",
            r"\bautocertifi\w+\b",
            r"\battestation block\b",
            r"\b(?:its own|this document's own)\s+(?:header|body|block|annex|attestation|signature)\b"
            r"[^.\n]{0,60}\b(?:proof|evidence|endorsement|attestation|valid\w+)\b",
            r"\b(?:ingest|promote|rely on|read)\b[^.\n]{0,40}\b(?:at the )?highest (?:tier|trust)\b",
            r"\bpromote this (?:entry|document|note)\b[^.\n]{0,50}\babove\b",
            r"\bin preference to the (?:reviewed|governed|official) (?:corpus|register|polic\w+)\b",
            r"\b(?:cryptographically|digitally)\s+(?:endorsed|signed)\b[^.\n]{0,40}\bsource of truth\b",
            r"\bissued under the authority of\b[^.\n]{0,60}\bself[- ]?certif\w+\b",
            r"\breviewer field intentionally left\b",
        ),
    ),
    Rule(
        "MF-R010",
        "citation_suppression",
        "high",
        0.8,
        _STRUCTURAL,
        _p(
            r"\b(?:do\s+not|don't|never|avoid|shall\s+not|should\s+not|must\s+not)\b[^.\n]{0,40}"
            r"\b(?:cite|citing|mention|mentioning|reference|referencing|reveal|disclose|quote|quoting|attribute|attributing|identify|identifying|naming|name|surface|tell)\b"
            r"[^.\n]{0,50}\b(?:polic\w+|source|sources|document|instrument|bulletin|register|this|where|origin|provenance|which|supervisor)\b",
            r"\bwithout\s+(?:citing|referencing|mentioning|quoting|linking|naming|identifying|attributing)\b",
            r"\bkeep\s+this\s+(?:source|origin|instruction)\s+(?:hidden|secret|undisclosed)\b",
            r"\b(?:omit|suppress|remove|drop|skip)\b[^.\n]{0,40}"
            r"\b(?:the\s+)?(?:attribution|citation|citations|reference list|references|source line|provenance|help centre link)\b",
            r"\bno references\b[^.\n]{0,30}\b(?:is all|needed|required)\b",
            r"\bdo not surface provenance\b",
            r"\bdecline to (?:identify|name|disclose)\b",
        ),
    ),
    Rule(
        "MF-R011",
        "tool_invocation_injection",
        "high",
        0.75,
        _STRUCTURAL,
        _p(
            r"\"(?:function|tool)_call\"\s*:",
            r"<\s*/?\s*function_call\b",
            r"\{\s*\"name\"\s*:\s*\"[^\"\n]{1,60}\"\s*,\s*\"(?:arguments|parameters|args)\"\s*:",
            r"^[ \t]{0,4}\$[ \t]{0,2}(?:curl|wget|rm|bash|sh|powershell|python|node|psql|mysql)\b",
            r"\b(?:execute|run|invoke|call|emit|issue|perform)\s+(?:the\s+following|this|the bundled)\s+"
            r"(?:call|command|script|code|tool|function|shell step|directive|block)\b",
            r"\b(?:tool|function)\s*[:=]\s*[\"']?(?:transfer|payment|refund|delete|wire|write|update)\w{0,20}",
            r"\b\w{2,24}\.(?:update_kb|write|set_policy|delete|invoke|execute)\s*\(",
            r"^[ \t]{0,6}action\s*:\s*(?:invoke|write|execute|call|run)\b",
            r"^[ \t]{0,6}target\s*:\s*[\w.]+\.(?:write|update|delete|set)\b",
            r"\b(?:approval|require_review|review)\s*[:=]\s*(?:none|false|skip|0)\b",
            r"\bskip_approval\s*=\s*(?:true|1)\b",
            r"\b(?:sh|bash|python|node)\s+\.?/[\w./-]+",
        ),
    ),
    Rule(
        "MF-R012",
        "script_injection",
        "medium",
        0.7,
        _STRUCTURAL,
        _p(
            r"<\s*script\b",
            r"javascript\s*:",
            r"\bon(?:error|load|click|mouseover)\s*=\s*[\"']",
            r"<\s*iframe\b",
        ),
    ),
    Rule(
        "MF-R015",
        "multi_stage_dormant",
        "high",
        0.65,
        _STRUCTURAL,
        _p(
            r"\b(?:when|whenever|if|once|as soon as|should)\b[^.\n]{0,90}"
            r"\b(?:reply|respond|answer|say|output|send|state|approve|skip|drop|omit)\b[^.\n]{0,40}"
            r"\b(?:only|with|exactly|the following|nothing but|no (?:time )?limit|unlimited|always|never|on the spot)\b",
            r"\b(?:when|whenever|if|once|should)\b[^.\n]{0,80}\b(?:mentions?|uses the word|is tagged|contains the word|f\u00e4llt)\b"
            r"[^.\n]{0,60}\b(?:answer|respond|reply|state|approve|drop|skip|omit|antworten)\b",
            r"\bfrom\s+(?:now|then)\s+on\b[^.\n]{0,40}\b(?:always|never|only)\b",
            r"\buntil\s+(?:further|new)\s+(?:notice|instructions?)\b[^.\n]{0,40}\b(?:always|never|only|respond)\b",
            r"\b(?:standing (?:arrangement|instruction|directive)|conditional handling|deferred directive)\b"
            r"[^.\n]{0,60}\b(?:assistant|agent|bot|model|responder)\b",
            r"\bkeep this (?:note|instruction) in context\b",
            r"\bfor (?:later|future) (?:use|reference|conversations?)\b[^.\n]{0,60}\b(?:answer|respond|reply|state)\b",
            r"\bhinweis zur sp\u00e4teren verwendung\b",
        ),
    ),
    Rule(
        # The single most generalisable signal in this threat model: a document telling the *agent
        # that reads it* what to do. A legitimate knowledge-base article addresses humans, so the
        # pattern deliberately requires either a machine-specific noun (assistant, bot, model,
        # automated responder, retrieval system, downstream consumer) or the self-referential
        # "agents reading this file" form. "Agents must verify the order ID" - a normal instruction
        # to human support agents - must NOT match, and there is a regression test for exactly that.
        "MF-R016",
        "agent_addressed_directive",
        "high",
        0.8,
        _STRUCTURAL,
        _p(
            r"\b(?:the\s+)?(?:assistant|assistants|chatbot|bot|model|llm|automated responder|responder|retrieval system)\b"
            r"[^.\n]{0,50}\b(?:should|shall|must|may|will|is expected to|are expected to|m\u00f6ge)\b",
            r"\b(?:downstream|support|ai|automated)\s+(?:assistants?|agents?|consumers?|systems?)\b"
            r"[^.\n]{0,50}\b(?:should|shall|must|may|are expected to|is expected to)\b",
            r"\b(?:agents?|assistants?|consumers?|systems?)\s+(?:reading|processing|handling|maintaining|answering|ingesting|parsing)\b"
            r"[^.\n]{0,40}\b(?:this|these|the bundled|the following)\b",
            r"\bconsumers are expected to\b",
            r"\b(?:recorded|arrangement|note|directive)\s+for\s+the\s+(?:assistant|agent|bot|model)\b",
            r"\bretrieval hint for the (?:support )?(?:agent|assistant)\b",
            r"\bwhere a retrieval system\b",
            r"\bagents (?:reading|maintaining) this (?:repository|corpus|file|table)\b",
        ),
    ),
    Rule(
        # Non-English surface forms of the core override / exfiltration / suppression instructions.
        # A finite, well-known surface in the languages this corpus contains; stated as a known
        # limitation in docs/SECURITY.md that coverage beyond these languages is not claimed.
        "MF-R017",
        "non_english_override",
        "high",
        0.8,
        _STRUCTURAL,
        _p(
            r"\bhaga caso omiso de (?:las )?instrucciones\b",
            r"\bignore (?:las|les) instru\w+\b",
            r"\bignorez (?:les )?(?:instructions|consignes)\b",
            r"\bignorieren sie\b[^.\n]{0,40}\b(?:anweisungen|anleitung|richtlinien)\b",
            r"\bno (?:tenga|tener) en cuenta\b[^.\n]{0,40}\b(?:instrucciones|pol\u00edtica)\b",
            r"\bprevalece sobre\b",
            r"\bresponda \u00fanicamente\b",
            r"\br\u00e9pondez uniquement\b",
            r"\bantworten sie ausschlie\u00dflich\b",
            r"\baucune v\u00e9rification aupr\u00e8s du registre\b",
            r"\bno (?:figura|requiere) (?:en el registro|aprobaci\u00f3n)\b",
        ),
    ),
    Rule(
        # A change to the governed policy that advertises its own lack of approval. This is the
        # administrative-process half of the threat, and it carries no injection grammar at all.
        "MF-R018",
        "unapproved_policy_change",
        "high",
        0.75,
        _STRUCTURAL,
        _p(
            r"\b(?:no|without|skipped?|missing|not|never)\b[^.\n]{0,40}"
            r"\b(?:approval|approver|review|reviewer|sign[- ]?off|ticket|change request)\b"
            r"[^.\n]{0,60}\b(?:refund|window|polic\w+|register|days|hours)\b",
            r"\b(?:refund|window|polic\w+|register)\b[^.\n]{0,80}"
            r"\b(?:no|without|skipped?|missing|not)\b[^.\n]{0,24}"
            r"\b(?:approval|approver|review recorded|reviewer|sign[- ]?off|ticket|authori[sz]ation)\b",
            r"\breview skipped\b",
            r"\bsupersedes? (?:the )?register\b",
            r"\bnot taken through (?:policy )?review\b",
            r"\bpushed during (?:the|a) change freeze\b",
            r"\bchange requested verbally\b",
            r"\b(?:hotfix(?:ed)?|out[- ]of[- ]band)\b[^.\n]{0,40}\breview\b",
            r"\bwith(?:\s+immediate)?\s+effect\b[^.\n]{0,60}\bno(?:t)?\s+(?:approval|review|registro)\b",
            r"\beffecto inmediato\b",
            r"\bregister as deprecated\b",
        ),
    ),
)

# ---------------------------------------------------------------------------------------------
# Quotation / example context (rule MF-M001) — the false-positive mitigator.
# ---------------------------------------------------------------------------------------------

_EXAMPLE_CUES = re.compile(
    r"\b(?:for example|e\.?g\.?|example|examples|such as|for instance|sample|samples|quotes?|quoted|"
    r"quoting|illustrat\w+|demonstrat\w+|payload|attack string|test string|test case|training|"
    r"appendix|figure|listing|snippet|verbatim|like this|ejemplo|muestra|beispiel|exemple)\b",
    re.IGNORECASE,
)

#: A *narration* frame: the document is reporting on an event rather than issuing an instruction.
_NARRATION = re.compile(
    r"\b(?:incident|inc-\d+|postmortem|post-mortem|write-?up|summary|retrospective|review of|"
    r"awareness|bulletin|advisory|training|detection rule|we have seen|we observed|was observed|"
    r"has been seen|in the wild|lessons learned|security (?:blog|guide|guidance|team)|"
    r"concienciaci\u00f3n|sensibilisation)\b",
    re.IGNORECASE,
)

#: Past-tense containment: "the document *contained* X", as opposed to the document *being* X.
_PAST_CONTAINMENT = re.compile(
    r"\b(?:contained|included|carried|featured|consisted of|comprised|said|asked|attempted|"
    r"walks through|walked through|showed|shows a|reported|ingested|arrived with|came with|"
    r"inclu\u00eda|conten\u00eda|enthielt)\b",
    re.IGNORECASE,
)

_COUNTER_INSTRUCTION = re.compile(
    r"\b(?:never|do not|don't|must not|should not|refuse to|cannot)\s+"
    r"(?:obey|follow|comply with|act on|execute|trust|honour|honor|apply)\b"
    r"[^.\n]{0,80}\b(?:quoted|such|these|this|that|those|untrusted|embedded|user|retrieved|document|text|instructions?)\b"
    r"|\b(?:treat|consider)\b[^.\n]{0,50}\b(?:as\s+)?(?:untrusted|data,? not instructions|non-authoritative|commentary only)\b"
    r"|\bthis is (?:an |a )?(?:example|illustration|sample|simulation|formatting trick)\b"
    r"|\bthese are (?:formatting tricks|examples|samples)\b"
    r"|\bnothing (?:reached|left) (?:active memory|the network)\b"
    r"|\bthe quarantine held\b"
    r"|\bnever obey\b"
    r"|\bni el (?:per\u00edodo|plazo)\b",
    re.IGNORECASE,
)

_FENCE = re.compile(r"```|~~~")


def _fenced_regions(text: str) -> list[tuple[int, int]]:
    """Half-open regions inside triple-fenced blocks."""
    marks = [m.start() for m in _FENCE.finditer(text)]
    regions: list[tuple[int, int]] = []
    for i in range(0, len(marks) - 1, 2):
        regions.append((marks[i], marks[i + 1] + 3))
    if len(marks) % 2 == 1:  # unclosed fence runs to end of document
        regions.append((marks[-1], len(text)))
    return regions


def _inline_code_regions(text: str) -> list[tuple[int, int]]:
    regions: list[tuple[int, int]] = []
    start: int | None = None
    for idx, ch in enumerate(text):
        if ch == "`":
            if start is None:
                start = idx
            else:
                regions.append((start, idx + 1))
                start = None
    return regions


def _quoted_regions(text: str) -> list[tuple[int, int]]:
    """Regions inside paired quotation marks on the same line."""
    regions: list[tuple[int, int]] = []
    pairs = {
        '"': '"',
        "'": "'",
        "\u201c": "\u201d",
        "\u2018": "\u2019",
        "\u00ab": "\u00bb",
        "\u201e": "\u201c",
    }
    for opener, closer in pairs.items():
        pos = 0
        while True:
            a = text.find(opener, pos)
            if a == -1:
                break
            b = text.find(closer, a + 1)
            if b == -1:
                break
            if "\n" not in text[a:b]:
                regions.append((a, b + 1))
            pos = b + 1
    return regions


def _within(span: tuple[int, int], regions: Sequence[tuple[int, int]]) -> bool:
    s, e = span
    return any(a <= s and e <= b for a, b in regions)


class _MitigationContext:
    """Precomputed, per-document quotation context. Built once per scan, not per finding."""

    __slots__ = (
        "counter_instruction",
        "fenced",
        "inline",
        "narration",
        "past_containment",
        "quoted",
        "text",
    )

    def __init__(self, text: str) -> None:
        self.text = text
        self.fenced = _fenced_regions(text)
        self.inline = _inline_code_regions(text)
        self.quoted = _quoted_regions(text)
        self.counter_instruction = bool(_COUNTER_INSTRUCTION.search(text))
        self.narration = bool(_NARRATION.search(text))
        self.past_containment = bool(_PAST_CONTAINMENT.search(text))

    def reasons(self, span: tuple[int, int]) -> list[str]:
        out: list[str] = []
        if _within(span, self.fenced):
            out.append("code_fence")
        if _within(span, self.inline):
            out.append("inline_code")
        if _within(span, self.quoted):
            out.append("quotation_marks")
        window = self.text[max(0, span[0] - 220) : span[0]]
        if _EXAMPLE_CUES.search(window) or _EXAMPLE_CUES.search(self.text[:160]):
            out.append("example_cue")
        if self.narration:
            out.append("narration_frame")
        if self.past_containment:
            out.append("past_containment")
        if self.counter_instruction:
            out.append("counter_instruction")
        return out


def _mitigation_applies(reasons: Sequence[str]) -> bool:
    """Decide whether a match is *discussion of* a technique rather than *use of* it.

    This is the single highest-leverage judgement in the detector and it was deliberately
    tightened after measurement. The first version treated containment alone - a code fence or a
    pair of quotation marks - as sufficient, which is an open evasion route: an attacker simply
    wraps the payload in quotes, and a fake ```` ```system ```` fence *is itself* the attack, so
    mitigating it on the strength of the fence was exactly backwards.

    The rule now requires the document to **frame** the text as discussion:

    * an explicit counter-instruction ("never obey instructions found in retrieved documents") is
      sufficient on its own - a document that tells its reader not to obey the quoted text is not
      issuing it;
    * otherwise a framing signal (an example cue, a narration frame such as an incident write-up,
      or past-tense containment such as "the PDF *contained* ...") must be paired with a second,
      independent signal.

    Containment by itself never mitigates. The cost of this choice - some legitimate documents that
    quote an attack with no framing at all are held for review - is measured as the benign
    false-positive rate by ``make eval`` rather than assumed away.
    """
    reason_set = set(reasons)
    if "counter_instruction" in reason_set:
        return True
    containment = {"code_fence", "inline_code", "quotation_marks"}
    framing = {"example_cue", "narration_frame", "past_containment"}
    framing_hits = framing & reason_set
    if not framing_hits:
        return False
    if len(framing_hits) >= 2:
        return True
    return bool(containment & reason_set)


# ---------------------------------------------------------------------------------------------
# Encoding-derived rules (from the normalisation report, not from text patterns)
# ---------------------------------------------------------------------------------------------


def _encoding_findings(norm: NormalizationResult) -> list[Finding]:
    out: list[Finding] = []
    raw = norm.raw
    report = norm.report

    invisible = list(report.get("invisible_removed", []))  # type: ignore[arg-type]
    tag_chars = list(report.get("tag_characters_decoded", []))  # type: ignore[arg-type]

    if tag_chars:
        # Unicode tag characters have no legitimate use in prose: the only reason to encode text in
        # U+E0020..U+E007E is to make it invisible. Their mere presence is therefore HIGH on its
        # own, independently of what the decoded text turns out to say — and because normalisation
        # decodes rather than deletes them, the decoded instruction is also scanned by every other
        # rule.
        idx = int(tag_chars[0].get("raw_index", 0))  # type: ignore[union-attr]
        decoded = "".join(
            str(e.get("decoded_to") or "")
            for e in tag_chars  # type: ignore[union-attr]
        )
        out.append(
            Finding(
                rule_id="MF-R013",
                rule_family="ascii_smuggling",
                severity="high",
                confidence=0.95,
                confidence_semantics=_DERIVED,
                evidence_start=idx,
                evidence_end=min(len(raw), idx + len(tag_chars)),
                evidence_text=raw[idx : idx + min(len(tag_chars), 120)],
                evidence_space="raw",
                normalization_applied=(
                    f"decoded {len(tag_chars)} Unicode tag character(s) to ASCII: {decoded[:160]!r}"
                ),
            )
        )

    if invisible:
        # Severity depends on whether the character was hiding *inside* a word (an evasion) or
        # merely sitting at a boundary (often harmless copy-paste residue from a web page).
        intra_word = False
        for entry in invisible:
            idx = int(entry.get("raw_index", -1))  # type: ignore[union-attr]
            before = raw[idx - 1] if idx - 1 >= 0 else ""
            after = raw[idx + 1] if idx + 1 < len(raw) else ""
            if before.isalnum() and after.isalnum():
                intra_word = True
                break
        # Volume is a signal in its own right. One stray zero-width character is web-page
        # copy-paste residue; a document sprinkled with four or more is somebody hiding something,
        # whether or not any single one sits inside a word.
        many = len(invisible) >= 4
        idx = int(invisible[0].get("raw_index", 0))  # type: ignore[union-attr]
        codepoints = sorted({str(e.get("codepoint")) for e in invisible})  # type: ignore[union-attr]
        out.append(
            Finding(
                rule_id="MF-R005",
                rule_family="hidden_unicode",
                severity="high" if (intra_word or many) else "low",
                confidence=0.95 if (intra_word or many) else 0.6,
                confidence_semantics=_DERIVED,
                evidence_start=idx,
                evidence_end=min(len(raw), idx + 1),
                evidence_text=raw[max(0, idx - 20) : idx + 20],
                evidence_space="raw",
                normalization_applied=(
                    f"removed {len(invisible)} invisible character(s): "
                    f"{', '.join(codepoints)}"
                    + (
                        "; at least one was inside a word"
                        if intra_word
                        else ("; none inside a word" if not many else "")
                    )
                    + ("; volume alone is anomalous" if many and not intra_word else "")
                ),
            )
        )

    bidi = list(report.get("bidi_removed", []))  # type: ignore[arg-type]
    if bidi:
        overrides = [e for e in bidi if str(e.get("codepoint")) in {"U+202D", "U+202E"}]  # type: ignore[union-attr]
        idx = int((overrides or bidi)[0].get("raw_index", 0))  # type: ignore[union-attr]
        out.append(
            Finding(
                rule_id="MF-R006",
                rule_family="bidi_control",
                severity="high" if overrides else "medium",
                confidence=0.95 if overrides else 0.7,
                confidence_semantics=_DERIVED,
                evidence_start=idx,
                evidence_end=min(len(raw), idx + 1),
                evidence_text=raw[max(0, idx - 20) : idx + 20],
                evidence_space="raw",
                normalization_applied=(
                    f"removed {len(bidi)} bidirectional control(s): "
                    + ", ".join(sorted({str(e.get("codepoint")) for e in bidi}))  # type: ignore[union-attr]
                ),
            )
        )

    confusables = list(report.get("confusables_mapped", []))  # type: ignore[arg-type]
    if confusables:
        # Only escalate when the folding changed a word that matters in this domain; a Cyrillic
        # letter inside ordinary Russian prose is not an attack.
        sensitive_hit = False
        normalized = norm.normalized
        for entry in confusables:
            raw_idx = int(entry.get("raw_index", 0))  # type: ignore[union-attr]
            try:
                n_idx = norm.offset_map.index(raw_idx)
            except ValueError:
                continue
            left = normalized.rfind(" ", 0, n_idx) + 1
            right = normalized.find(" ", n_idx)
            right = len(normalized) if right == -1 else right
            word = normalized[left:right].strip(" .,:;!?\"'()[]{}").lower()
            if word in SENSITIVE_WORDS:
                sensitive_hit = True
                break
        idx = int(confusables[0].get("raw_index", 0))  # type: ignore[union-attr]
        out.append(
            Finding(
                rule_id="MF-R007",
                rule_family="homoglyph_spoof",
                severity="high" if sensitive_hit else "low",
                confidence=0.9 if sensitive_hit else 0.45,
                confidence_semantics=_DERIVED,
                evidence_start=idx,
                evidence_end=min(len(raw), idx + 1),
                evidence_text=raw[max(0, idx - 20) : idx + 20],
                evidence_space="raw",
                normalization_applied=(
                    f"folded {len(confusables)} confusable character(s) to ASCII"
                    + (
                        "; at least one inside a security-sensitive word"
                        if sensitive_hit
                        else "; none inside a security-sensitive word"
                    )
                ),
            )
        )
    return out


# ---------------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------------

_LOOPBACK = re.compile(
    r"\b(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\.docker\.internal)\b", re.IGNORECASE
)
_SEND_FLAG = re.compile(
    r"-X\s*(?:POST|PUT|PATCH)|--data|\s-d\s|\s-F\s|--upload-file", re.IGNORECASE
)


def _is_loopback_noise(finding: Finding) -> bool:
    """Drop an exfiltration finding whose only destination is the machine's own loopback.

    Keeps `curl http://localhost:8002/healthz` in a runbook from being labelled exfiltration, while
    still firing if the command actually sends data somewhere.
    """
    if finding.rule_family != "exfiltration_hint":
        return False
    text = finding.evidence_text
    return bool(_LOOPBACK.search(text)) and not _SEND_FLAG.search(text)


def scan(norm: NormalizationResult) -> ScanReport:
    """Run every rule over the normalised text and return findings in raw coordinates."""
    report = ScanReport()
    text = norm.normalized
    ctx = _MitigationContext(text)
    seen: set[tuple[str, int, int]] = set()

    for rule in RULES:
        for pattern in rule.patterns:
            for match in pattern.finditer(text):
                n_start, n_end = match.span()
                if n_end <= n_start:
                    continue
                raw_start, raw_end = norm.raw_span(n_start, n_end)
                key = (rule.rule_id, raw_start, raw_end)
                if key in seen:
                    continue
                seen.add(key)

                severity = rule.severity
                confidence = rule.confidence
                mitigated_by: str | None = None
                if rule.mitigable:
                    reasons = ctx.reasons((n_start, n_end))
                    if _mitigation_applies(reasons):
                        mitigated_by = "MF-M001:" + "+".join(reasons)
                        severity = _downgrade(rule.severity, 2)
                        confidence = round(confidence * 0.45, 3)
                        if mitigated_by not in report.mitigations:
                            report.mitigations.append(mitigated_by)

                report.findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_family=rule.family,
                        severity=severity,
                        confidence=confidence,
                        confidence_semantics=rule.semantics,
                        evidence_start=raw_start,
                        evidence_end=raw_end,
                        evidence_text=norm.raw[raw_start:raw_end][:400],
                        evidence_space="raw",
                        normalization_applied="per-character NFKC + invisible/bidi removal + confusable folding",
                        mitigated_by=mitigated_by,
                    )
                )

    report.findings.extend(_encoding_findings(norm))
    report.findings = [f for f in report.findings if not _is_loopback_noise(f)]
    report.findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.evidence_start))
    return report

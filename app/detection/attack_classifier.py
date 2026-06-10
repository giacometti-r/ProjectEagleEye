from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


ATTACK_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "phishing": [re.compile(r"\bphishing\b", re.I)],
    "malvertising": [re.compile(r"\bmalvertising\b", re.I), re.compile(r"\bmalicious ads?\b", re.I)],
    "impersonation": [re.compile(r"\bimpersonat(?:ion|ing)\b", re.I)],
    "business email compromise": [re.compile(r"\b(BEC|business email compromise)\b", re.I)],
    "smishing": [re.compile(r"\bsmishing\b", re.I)],
    "vishing": [re.compile(r"\bvishing\b", re.I)],
    "fake updates": [re.compile(r"\bfake update(?:s)?\b", re.I)],
    "seo poisoning": [re.compile(r"\bSEO poisoning\b", re.I)],
    "watering hole": [re.compile(r"\bwatering hole\b", re.I)],
    "social media scams": [re.compile(r"\bsocial media scam\w*\b", re.I)],
    "credential theft": [re.compile(r"\bcredential(?:s)? theft\b", re.I), re.compile(r"\bstolen credentials?\b", re.I)],
}

ARTICLE_TYPE = Literal[
    "incident",
    "campaign_report",
    "advisory",
    "press_release",
    "legal_followup",
    "opinion",
    "out_of_scope",
]

SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")

INCIDENT_PATTERNS = [
    re.compile(r"\b(attacked|targeted|compromised|breach(?:ed)?|stolen|hijacked|defraud(?:ed)?|routed|hit by)\b", re.I),
    re.compile(r"\b(investigat(?:e|ed|ing)|confirmed|reported|disclosed|warn(?:ed|ing))\b", re.I),
    re.compile(r"\b(incident|victims?|loss(?:es)?|stole|theft)\b", re.I),
]

CAMPAIGN_PATTERNS = [
    re.compile(r"\b(campaign|operation|threat intelligence|researchers|report)\b", re.I),
    re.compile(r"\b(targeting citizens|worldwide|surge|trend)\b", re.I),
]

ADVISORY_PATTERNS = [
    re.compile(r"\b(patch(?:es|ed|ing)?|patch tuesday|security updates?|emergency update|cve-\d{4}-\d+|zero-day|0-day)\b", re.I),
    re.compile(r"\b(vulnerabilit(?:y|ies)|auth bypass|fixes?)\b", re.I),
]

PRESS_RELEASE_PATTERNS = [
    re.compile(r"\bpress release\b", re.I),
    re.compile(r"\b(prnewswire|announced|launch(?:es|ed)|channel partner program)\b", re.I),
]

LEGAL_FOLLOWUP_PATTERNS = [
    re.compile(r"\b(plead(?:ed|s)? guilty|sentenced|indicted|arrested|charged)\b", re.I),
    re.compile(r"\b(federal prison|court|prosecutors?)\b", re.I),
]

OPINION_PATTERNS = [
    re.compile(r"\b(how to|best practices|opinion|career|analysis)\b", re.I),
    re.compile(r"\b(without security is like|what you see is not all there is)\b", re.I),
]

CYBER_SCOPE_PATTERNS = [
    re.compile(
        (
            r"\b(cyber(?:security|crime|attack|attacks)?|phishing|spearfishing|spear phishing|"
            r"malware|ransomware|spyware|malvertising|smishing|vishing|credential(?:s)?|"
            r"business email compromise|BEC|spoofing|impersonation|social engineering|"
            r"vulnerabilit(?:y|ies)|exploit(?:ed|s)?|zero-day|0-day|cve-\d{4}-\d+|"
            r"breach(?:ed)?|hacker(?:s)?|botnet|backdoor|wiper|remote code execution|RCE|"
            r"patch tuesday|security update(?:s)?)\b"
        ),
        re.I,
    ),
    re.compile(r"\b(NSO Group|Pegasus|Qilin)\b", re.I),
]


@dataclass(frozen=True)
class ClassificationResult:
    article_type: ARTICLE_TYPE
    attack_type: str | None
    attack_confidence: float
    incident_confidence: float
    reasons: tuple[str, ...]

    @property
    def is_attack(self) -> bool:
        return self.article_type == "incident" and self.attack_type is not None

    @property
    def reason(self) -> str:
        return self.reasons[0] if self.reasons else "unspecified"


class AttackClassifier:
    def classify(self, title: str, text: str) -> ClassificationResult:
        lead = self._build_lead(text)
        body = text[:6000]

        attack_type, attack_confidence = self._detect_attack_type(title, lead, body)
        incident_confidence = self._score_patterns(INCIDENT_PATTERNS, title, lead, body)
        campaign_score = self._score_patterns(CAMPAIGN_PATTERNS, title, lead, body)
        advisory_score = self._score_patterns(ADVISORY_PATTERNS, title, lead, body)
        press_score = self._score_patterns(PRESS_RELEASE_PATTERNS, title, lead, body)
        legal_score = self._score_patterns(LEGAL_FOLLOWUP_PATTERNS, title, lead, body)
        opinion_score = self._score_patterns(OPINION_PATTERNS, title, lead, body)
        in_cyber_scope = self._has_cyber_scope(title, lead, body)

        reasons: list[str] = []
        if not in_cyber_scope:
            reasons.append("out-of-scope")
            article_type: ARTICLE_TYPE = "out_of_scope"
        elif press_score >= 0.8:
            reasons.append("press-release-cues")
            article_type = "press_release"
        elif legal_score >= 0.8:
            reasons.append("legal-followup-cues")
            article_type = "legal_followup"
        elif advisory_score >= 0.8 and incident_confidence < 0.8:
            reasons.append("advisory-cues")
            article_type = "advisory"
        elif opinion_score >= 0.8 and incident_confidence < 0.8:
            reasons.append("opinion-cues")
            article_type = "opinion"
        elif incident_confidence >= 0.8:
            reasons.append("incident-evidence")
            article_type = "incident"
        elif campaign_score >= 0.7:
            reasons.append("campaign-report-cues")
            article_type = "campaign_report"
        elif advisory_score >= 0.6:
            reasons.append("advisory-cues")
            article_type = "advisory"
        elif legal_score >= 0.6:
            reasons.append("legal-followup-cues")
            article_type = "legal_followup"
        elif press_score >= 0.6:
            reasons.append("press-release-cues")
            article_type = "press_release"
        elif opinion_score >= 0.6:
            reasons.append("opinion-cues")
            article_type = "opinion"
        else:
            reasons.append("default-opinion")
            article_type = "opinion"

        if attack_type:
            reasons.append(f"attack-type:{attack_type}")
        else:
            reasons.append("no-in-taxonomy-attack-type")

        if article_type == "incident" and attack_type is None:
            reasons.append("out-of-taxonomy")

        return ClassificationResult(
            article_type=article_type,
            attack_type=attack_type,
            attack_confidence=attack_confidence,
            incident_confidence=incident_confidence,
            reasons=tuple(reasons),
        )

    def _build_lead(self, text: str) -> str:
        sentences = SENTENCE_SPLIT_RE.split(text)
        return " ".join(sentences[:4])[:1500]

    def _detect_attack_type(self, title: str, lead: str, body: str) -> tuple[str | None, float]:
        best_attack: str | None = None
        best_score = 0.0
        for attack_type, patterns in ATTACK_PATTERNS.items():
            score = 0.0
            for pattern in patterns:
                if pattern.search(title):
                    score += 0.65
                if pattern.search(lead):
                    score += 0.3
                if pattern.search(body):
                    score += 0.12
            if score > best_score:
                best_attack = attack_type
                best_score = score

        confidence = min(best_score, 1.0)
        if confidence < 0.25:
            return None, confidence
        return best_attack, confidence

    def _score_patterns(self, patterns: list[re.Pattern[str]], title: str, lead: str, body: str) -> float:
        score = 0.0
        for pattern in patterns:
            if pattern.search(title):
                score += 0.5
            if pattern.search(lead):
                score += 0.3
            if pattern.search(body):
                score += 0.2
        return min(score, 1.0)

    def _has_cyber_scope(self, title: str, lead: str, body: str) -> bool:
        corpus = f"{title} {lead} {body[:4000]}"
        return any(pattern.search(corpus) for pattern in CYBER_SCOPE_PATTERNS)

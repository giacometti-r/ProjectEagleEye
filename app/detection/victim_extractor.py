from __future__ import annotations

import re
from dataclasses import dataclass

ORG_CUES = {
    "company": ["inc", "corp", "ltd", "llc", "plc", "company", "co."],
    "government": ["ministry", "department", "government", "city of", "state of", "agency"],
    "university": ["university", "college", "institute", "school"],
    "hospital": ["hospital", "health", "healthcare", "clinic", "medical center", "nhs"],
}

VICTIM_PATTERNS = [
    re.compile(r"\b(?i:targeted|attacked|compromised|breached)\s+([A-Z][\w&.'\- ]{2,80})"),
    re.compile(r"\b([A-Z][\w&.'\- ]{2,80})\s+(?i:was|were)\s+(?i:targeted|attacked|compromised|breached)"),
    re.compile(r"\b(?i:targeting)\s+([A-Z][\w&.'\- ]{2,80})"),
    re.compile(r"\b(?i:attacks?)\s+(?i:against)\s+([A-Z][\w&.'\- ]{2,80})"),
    re.compile(r"\b([A-Z][\w&.'\- ]{2,80})\s+(?i:was|were)\s+(?i:hit)\s+(?i:by)\b"),
]

STOP_TOKENS = {"the", "a", "an", "this", "that", "these", "those", "phishing", "attack", "campaign"}
GENERIC_ENTITY_TERMS = {"officials", "students", "staff", "users", "customers", "people", "citizens", "workers", "devices"}
PRODUCT_FRAGMENT_TERMS = {
    "access",
    "browser",
    "chrome",
    "exchange",
    "outlook",
    "server",
    "servers",
    "sentry",
    "unifi",
    "vpn",
    "web",
    "windows",
}
NOISE_PATTERNS = [
    re.compile(r"\b(menu|news search|write for us|share on|comment|lifestyle|fashion|film)\b", re.I),
    re.compile(r"\b(english|ukrainska|japanese)\b", re.I),
    re.compile(r"\.(com|net|org|co\.uk)\b", re.I),
    re.compile(r"[.!?]\s+[A-Z]"),
    re.compile(r"\b(on monday|on tuesday|on wednesday|on thursday|on friday|on saturday|on sunday)\b", re.I),
    re.compile(r"\b(over new|to hack|violating court order|this high-severity)\b", re.I),
]


@dataclass(frozen=True)
class VictimResult:
    victim_name: str | None
    victim_category: str | None
    confidence: float
    reason: str


class VictimExtractor:
    def __init__(self, max_words: int = 8) -> None:
        self.max_words = max_words

    def extract(self, title: str, text: str) -> VictimResult:
        diagnostics = {"saw_generic_entity": False, "saw_noisy_candidate": False}

        title_candidates = self._collect_candidates(title, source_weight=0.65, diagnostics=diagnostics)
        body_candidates = self._collect_candidates(text[:1800], source_weight=0.4, diagnostics=diagnostics)

        for candidates, reason in (
            (title_candidates, "matched_title"),
            (body_candidates, "matched_body"),
        ):
            ranked = sorted(candidates, key=lambda x: x[2], reverse=True)
            for raw, category, confidence in ranked:
                normalized = self._finalize_name(raw)
                if normalized:
                    return VictimResult(normalized, category, confidence, reason)

        if diagnostics["saw_generic_entity"]:
            return VictimResult(None, None, 0.0, "generic_entity")
        if diagnostics["saw_noisy_candidate"]:
            return VictimResult(None, None, 0.0, "noisy_candidate")
        return VictimResult(None, None, 0.0, "no_named_org")

    def _collect_candidates(
        self,
        content: str,
        source_weight: float,
        diagnostics: dict[str, bool],
    ) -> list[tuple[str, str, float]]:
        results: list[tuple[str, str, float]] = []
        for pattern in VICTIM_PATTERNS:
            for match in pattern.finditer(content):
                raw = self._normalize_candidate(match.group(1))
                if not raw:
                    continue
                noisy_reason = self._noise_reason(raw)
                if noisy_reason == "generic_entity":
                    diagnostics["saw_generic_entity"] = True
                    continue
                if noisy_reason:
                    diagnostics["saw_noisy_candidate"] = True
                    continue
                category = self._classify_org(raw)
                if not category:
                    continue
                confidence = self._score_candidate(raw, category, source_weight)
                results.append((raw, category, confidence))
        return results

    def _normalize_candidate(self, raw: str) -> str | None:
        candidate = re.sub(r"\s+", " ", raw.strip(" .,:;|-"))
        if len(candidate) < 3:
            return None

        lowered = candidate.lower()
        if lowered in STOP_TOKENS:
            return None

        return candidate

    def _noise_reason(self, candidate: str) -> str | None:
        words = candidate.split()
        if len(words) > self.max_words:
            return "too_many_words"
        if any(word.lower() in GENERIC_ENTITY_TERMS for word in words):
            return "generic_entity"
        if any(word.lower().strip(".,:;") in PRODUCT_FRAGMENT_TERMS for word in words):
            return "product_fragment"
        if any(pattern.search(candidate) for pattern in NOISE_PATTERNS):
            return "navigation_noise"
        if candidate.count(" - ") >= 1:
            return "dash_noise"
        if sum(1 for c in candidate if c.isdigit()) > 3:
            return "digit_noise"
        return None

    def _score_candidate(self, name: str, category: str, source_weight: float) -> float:
        score = source_weight
        words = name.split()
        if 2 <= len(words) <= self.max_words:
            score += 0.15
        if category != "company":
            score += 0.15
        if any(token[:1].isupper() for token in words[:2]):
            score += 0.1
        return min(score, 1.0)

    def _finalize_name(self, name: str) -> str | None:
        words = name.split()
        if len(words) > self.max_words:
            words = words[: self.max_words]
        final = " ".join(words).strip(" .,:;|-")
        if len(final) < 3:
            return None
        return final

    def _classify_org(self, name: str) -> str | None:
        low = name.lower()
        for category, cues in ORG_CUES.items():
            if any(cue in low for cue in cues):
                return category

        words = name.split()
        if len(words) >= 2 and all(word[:1].isupper() for word in words[:2]):
            return "company"

        return None

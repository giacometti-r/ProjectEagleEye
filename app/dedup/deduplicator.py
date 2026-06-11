from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

TRACKING_QUERY_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
}

SOURCE_SUFFIX_RE = re.compile(r"\s+-\s+[\w .,&'()]{2,80}$")
SIMILARITY_PUNCT_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class SimilarityMatch:
    index: int
    score: float


@dataclass(frozen=True)
class SimilarityPair:
    left_index: int
    right_index: int
    score: float


@dataclass(frozen=True)
class TopicDuplicateMatch:
    index: int
    score: float
    shared_title_terms: tuple[str, ...]


TOPIC_TITLE_STOPWORDS = {
    "about",
    "after",
    "against",
    "amid",
    "and",
    "are",
    "from",
    "has",
    "have",
    "into",
    "its",
    "new",
    "news",
    "of",
    "on",
    "says",
    "said",
    "the",
    "this",
    "to",
    "using",
    "with",
    "warns",
    "warning",
    "cyber",
    "cybersecurity",
    "security",
    "attack",
    "attacks",
    "attacked",
    "campaign",
    "campaigns",
    "hackers",
    "malware",
    "microsoft",
    "phishing",
    "systems",
    "users",
    "windows",
}
TOPIC_TOKEN_ALIASES = {
    "agencies": "agency",
    "days": "day",
    "federal": "government",
    "firm": "company",
    "flaw": "vulnerability",
    "flaws": "vulnerability",
    "govt": "government",
    "patched": "patch",
    "patches": "patch",
    "patching": "patch",
    "takes": "take",
    "vulnerabilities": "vulnerability",
}


def normalize_incident_entity(value: str) -> str:
    lowered = value.lower()
    lowered = re.sub(r"[^a-z0-9 ]+", " ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    return lowered


def build_incident_key(victim_name: str, attack_type: str) -> str:
    normalized_victim = normalize_incident_entity(victim_name)
    normalized_attack = normalize_incident_entity(attack_type)
    token = f"{normalized_victim}|{normalized_attack}"
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def canonicalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    path = re.sub(r"/+", "/", parsed.path or "/")
    query_pairs = [
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=False)
        if k.lower() not in TRACKING_QUERY_PARAMS
    ]
    query = urlencode(sorted(query_pairs))

    canonical = urlunparse(
        (
            parsed.scheme.lower() or "https",
            parsed.netloc.lower(),
            path.rstrip("/") or "/",
            "",
            query,
            "",
        )
    )
    return canonical


def _normalize_text(text: str) -> str:
    cleaned = re.sub(r"\s+", " ", text.lower()).strip()
    return cleaned


def build_fingerprint(title: str, text: str) -> str:
    normalized = _normalize_text(f"{title} {text[:3000]}")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def build_content_hash(text: str) -> str:
    normalized = _normalize_text(text)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def build_similarity_document(title: str, abstract: str, text: str, text_prefix_chars: int = 4000) -> str:
    normalized_title = _normalize_similarity_text(SOURCE_SUFFIX_RE.sub("", title))
    normalized_abstract = _normalize_similarity_text(abstract)
    normalized_text = _normalize_similarity_text(text[:text_prefix_chars])
    return " ".join(
        part
        for part in (
            #normalized_title,
            #normalized_title,
            normalized_title,
            normalized_abstract,
            normalized_text,
        )
        if part
    )


def build_topic_document(title: str, abstract: str) -> str:
    normalized_title = _normalize_topic_text(SOURCE_SUFFIX_RE.sub("", title))
    normalized_abstract = _normalize_topic_text(abstract)
    return " ".join(
        part
        for part in (
            normalized_title,
            normalized_title,
            normalized_abstract,
        )
        if part
    )


def salient_title_tokens(title: str) -> set[str]:
    normalized_title = _normalize_topic_text(SOURCE_SUFFIX_RE.sub("", title))
    return {
        token
        for token in normalized_title.split()
        if len(token) > 2 and token not in TOPIC_TITLE_STOPWORDS
    }


def shared_salient_title_terms(left_title: str, right_title: str) -> tuple[str, ...]:
    left_tokens = salient_title_tokens(left_title)
    right_tokens = salient_title_tokens(right_title)
    shared = left_tokens & right_tokens
    if not shared:
        return ()

    union_size = max(len(left_tokens | right_tokens), 1)
    jaccard = len(shared) / union_size
    if len(shared) >= 2 or jaccard >= 0.25:
        return tuple(sorted(shared))
    return ()


def find_near_duplicate(
    candidate_document: str,
    existing_documents: list[str],
    threshold: float,
) -> SimilarityMatch | None:
    if not candidate_document.strip() or not existing_documents:
        return None

    documents = [candidate_document, *existing_documents]
    try:
        matrix = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1).fit_transform(documents)
    except ValueError:
        return None

    scores = cosine_similarity(matrix[0:1], matrix[1:]).ravel()
    if len(scores) == 0:
        return None

    best_index = int(scores.argmax())
    best_score = float(scores[best_index])
    if best_score < threshold:
        return None
    return SimilarityMatch(index=best_index, score=best_score)


def find_topic_duplicate(
    candidate_title: str,
    candidate_abstract: str,
    existing_items: list[tuple[str, str]],
    threshold: float,
) -> TopicDuplicateMatch | None:
    if not candidate_title.strip() or not existing_items:
        return None

    candidate_document = build_topic_document(candidate_title, candidate_abstract)
    existing_documents = [build_topic_document(title, abstract) for title, abstract in existing_items]
    if not candidate_document.strip() or not any(document.strip() for document in existing_documents):
        return None

    documents = [candidate_document, *existing_documents]
    try:
        matrix = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1).fit_transform(documents)
    except ValueError:
        return None

    scores = cosine_similarity(matrix[0:1], matrix[1:]).ravel()
    ranked_indices = sorted(range(len(scores)), key=lambda index: float(scores[index]), reverse=True)
    for index in ranked_indices:
        score = float(scores[index])
        if score < threshold:
            break
        shared_terms = shared_salient_title_terms(candidate_title, existing_items[index][0])
        if shared_terms:
            return TopicDuplicateMatch(index=index, score=score, shared_title_terms=shared_terms)
    return None


def find_near_duplicate_pairs(documents: list[str], threshold: float) -> list[SimilarityPair]:
    if len(documents) < 2 or not any(document.strip() for document in documents):
        return []

    try:
        matrix = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1).fit_transform(documents)
    except ValueError:
        return []

    scores = cosine_similarity(matrix)
    matches: list[SimilarityPair] = []
    for left_index in range(len(documents)):
        for right_index in range(left_index + 1, len(documents)):
            score = float(scores[left_index, right_index])
            if score >= threshold:
                matches.append(SimilarityPair(left_index=left_index, right_index=right_index, score=score))
    return matches


def _normalize_similarity_text(text: str) -> str:
    lowered = text.lower()
    lowered = re.sub(r"https?://\S+", " ", lowered)
    lowered = SIMILARITY_PUNCT_RE.sub(" ", lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def _normalize_topic_text(text: str) -> str:
    normalized = _normalize_similarity_text(text)
    return " ".join(TOPIC_TOKEN_ALIASES.get(token, token) for token in normalized.split())

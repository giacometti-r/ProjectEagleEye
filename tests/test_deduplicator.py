from app.dedup.deduplicator import (
    build_content_hash,
    build_fingerprint,
    build_incident_key,
    build_similarity_document,
    canonicalize_url,
    find_near_duplicate,
)


def test_canonicalize_url_removes_tracking() -> None:
    url = "https://example.com/path/?utm_source=x&id=10&utm_medium=y"
    assert canonicalize_url(url) == "https://example.com/path?id=10"


def test_fingerprint_is_stable_for_whitespace_changes() -> None:
    a = build_fingerprint("Title", "A lot of text here")
    b = build_fingerprint("Title", "A   lot\nof text here")
    assert a == b


def test_incident_key_is_stable_for_case_and_punctuation() -> None:
    a = build_incident_key("University of Cambridge", "Phishing")
    b = build_incident_key("university of cambridge!", "phishing")
    assert a == b


def test_content_hash_is_stable_for_whitespace_changes() -> None:
    a = build_content_hash("Same article text")
    b = build_content_hash("Same   article\ntext")
    assert a == b


def test_similarity_matches_exact_repeated_title() -> None:
    candidate = build_similarity_document(
        "Meta Accuses Pegasus Maker of New Spying Operations - tovima.com",
        "Meta says spyware activity continued against WhatsApp users.",
        "Meta accused NSO Group of renewed spyware operations targeting WhatsApp users.",
    )
    existing = [
        build_similarity_document(
            "Meta Accuses Pegasus Maker of New Spying Operations - tovima.com",
            "Meta says spyware activity continued against WhatsApp users.",
            "Meta accused NSO Group of renewed spyware activity involving WhatsApp.",
        )
    ]

    match = find_near_duplicate(candidate, existing, threshold=0.78)
    assert match is not None
    assert match.index == 0


def test_similarity_matches_source_suffix_title_variant() -> None:
    candidate = build_similarity_document(
        "WhatsApp says it disrupted new NSO spyware phishing attacks - BleepingComputer",
        "WhatsApp disrupted NSO-linked spyware phishing attacks.",
        "WhatsApp said it disrupted NSO spyware phishing attacks against users.",
    )
    existing = [
        build_similarity_document(
            "WhatsApp says it disrupted new NSO spyware phishing attacks",
            "WhatsApp disrupted NSO-linked spyware phishing activity.",
            "Meta said WhatsApp disrupted new spyware phishing attacks linked to NSO Group.",
        )
    ]

    assert find_near_duplicate(candidate, existing, threshold=0.78) is not None


def test_similarity_does_not_match_unrelated_advisories() -> None:
    candidate = build_similarity_document(
        "Google patches new Chrome zero-day flaw exploited in the wild",
        "Google shipped a Chrome security update for an exploited browser flaw.",
        "The Chrome team fixed a zero-day vulnerability exploited in attacks.",
    )
    existing = [
        build_similarity_document(
            "Microsoft patches Exchange Server zero-day exploited in attacks",
            "Microsoft released Exchange Server security updates.",
            "The Exchange Server advisory describes a spoofing vulnerability.",
        )
    ]

    assert find_near_duplicate(candidate, existing, threshold=0.78) is None

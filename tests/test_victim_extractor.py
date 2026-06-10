from app.detection.victim_extractor import VictimExtractor


def test_extracts_company_victim() -> None:
    extractor = VictimExtractor()
    result = extractor.extract(
        "Northwind Inc was targeted in a BEC attack",
        "Investigators said Northwind Inc was compromised after an impersonation campaign.",
    )
    assert result.victim_name is not None
    assert "Northwind" in result.victim_name
    assert result.victim_category == "company"
    assert result.confidence >= 0.65


def test_extracts_hospital_victim() -> None:
    extractor = VictimExtractor()
    result = extractor.extract(
        "Attackers breached Riverside Hospital",
        "The phishing attack targeted Riverside Hospital IT staff.",
    )
    assert result.victim_name is not None
    assert "Riverside Hospital" in result.victim_name
    assert result.victim_category == "hospital"
    assert result.confidence >= 0.65


def test_extracts_targeting_pattern_from_title() -> None:
    extractor = VictimExtractor()
    result = extractor.extract(
        "Signal phishing attack targeting University of Cambridge",
        "Officials said attackers sent malicious messages.",
    )
    assert result.victim_name == "University of Cambridge"
    assert result.reason == "matched_title"


def test_rejects_noisy_google_news_style_victim_candidate() -> None:
    extractor = VictimExtractor()
    result = extractor.extract(
        "German prosecutors investigate Signal phishing attack",
        (
            "News Search Thoughts About Write English English Українська 日本語 30 apr 2026 "
            "German prosecutors investigate Signal phishing attack that targeted government officials."
        ),
    )
    assert result.victim_name is None
    assert result.victim_category is None
    assert result.confidence == 0.0
    assert result.reason in {"generic_entity", "noisy_candidate", "no_named_org"}


def test_rejects_sentence_spillover_victim_candidate() -> None:
    extractor = VictimExtractor()
    result = extractor.extract(
        "Microsoft patches Exchange Server zero-day exploited in attacks",
        (
            "Researchers described attacks against Outlook Web Access users. "
            "This high-severity spoofing vulnerability was patched by Microsoft."
        ),
    )
    assert result.victim_name is None
    assert result.reason in {"noisy_candidate", "generic_entity", "no_named_org"}


def test_rejects_reporting_time_fragment_victim_candidate() -> None:
    extractor = VictimExtractor()
    result = extractor.extract(
        "Meta Stock: WhatsApp Takes Action Against NSO Group Spyware",
        "Meta said it took action against NSO Group on Monday after spyware activity.",
    )
    assert result.victim_name is None
    assert result.reason in {"noisy_candidate", "no_named_org"}


def test_rejects_product_fragment_victim_candidate() -> None:
    extractor = VictimExtractor()
    result = extractor.extract(
        "CISA gives feds 3 days to patch Check Point VPN bug exploited as zero-day",
        "The advisory warned attacks against Mobile Access appliances could lead to compromise.",
    )
    assert result.victim_name is None
    assert result.reason in {"noisy_candidate", "no_named_org"}


def test_rejects_generic_users_as_victim() -> None:
    extractor = VictimExtractor()
    result = extractor.extract(
        "Meta Accuses Pegasus Maker NSO Of Targeting WhatsApp Users To Hack Their Devices",
        "The spyware firm was targeting WhatsApp Users To Hack Their Devices through phishing.",
    )
    assert result.victim_name is None
    assert result.reason in {"generic_entity", "noisy_candidate", "no_named_org"}

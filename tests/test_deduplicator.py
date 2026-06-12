from app.dedup.deduplicator import (
    build_content_hash,
    build_fingerprint,
    build_incident_key,
    build_similarity_document,
    canonicalize_url,
    find_near_duplicate,
    find_topic_duplicate,
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

    match = find_near_duplicate(candidate, existing, threshold=0.30)
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

    assert find_near_duplicate(candidate, existing, threshold=0.30) is not None


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

    assert find_near_duplicate(candidate, existing, threshold=0.30) is None


def test_topic_duplicate_matches_digest_rewrite_examples() -> None:
    examples = [
        (
            "Meta takes legal action against Israeli spyware firm NSO - The Straits Times",
            "These attempts were similar to previous one-click phishing campaigns aimed at WhatsApp users.",
            "Meta to take legal action against Israeli spyware company NSO - Al Jazeera",
            "Meta said NSO spyware operators targeted WhatsApp users with one-click phishing attempts.",
        ),
        (
            "CISA tells govt agencies to patch critical exploited flaws in 3 days",
            "CISA ordered federal agencies to patch high-risk exploited vulnerabilities within three days.",
            "CISA to require federal agencies to patch some cyber vulnerabilities within 3 days",
            "The agency will require faster patching for vulnerabilities facing the highest risk.",
        ),
        (
            "Tax-Themed Phishing Emails Deliver In-Memory Malware to Windows Users - cyberpress.org",
            "Tax phishing emails are being used to deliver in-memory malware to Windows systems.",
            "Hackers Use Tax Phishing Emails to Deploy In-Memory Malware on Windows Systems - CyberSecurityNews",
            "Researchers warned that tax-themed phishing messages deploy fileless malware on Windows.",
        ),
        (
            "UNC3753 Targets US Law Firms with Vishing, RMM Tools, and Physical Break-Ins - gbhackers.com",
            "UNC3753 is targeting law firms with vishing, remote management tools, and physical intrusion.",
            "UNC3753 Attacking US Law Firms Using Vishing and RMM Tools to Exfiltrate Data - CyberSecurityNews",
            "The threat group used vishing and RMM tools against United States law firms.",
        ),
    ]

    for candidate_title, candidate_abstract, existing_title, existing_abstract in examples:
        match = find_topic_duplicate(
            candidate_title,
            candidate_abstract,
            "",
            [(existing_title, existing_abstract, "")],
            threshold=0.30,
        )
        assert match is not None, candidate_title
        assert match.index == 0


def test_topic_duplicate_uses_article_text_when_abstracts_are_weak() -> None:
    match = find_topic_duplicate(
        "AI brands as bait: How threat actors are using the AI hype in social engineering - Microsoft",
        "Security researchers warned about evolving social engineering activity.",
        (
            "Threat actors are using trusted AI brands as bait in phishing, malvertising, and search "
            "engine optimization abuse. Campaigns impersonate OpenAI, Anthropic, and DeepSeek to lure "
            "victims into credential theft pages and malicious downloads."
        ),
        [
            (
                "Hackers are capitalizing on AI hype to ramp up social engineering attacks - IT Pro",
                "Researchers reported an uptick in attacks.",
                (
                    "Microsoft Threat Intelligence observed phishing, malvertising, and SEO poisoning "
                    "campaigns using AI brands as bait. Attackers impersonated OpenAI, Anthropic, and "
                    "DeepSeek to lure victims into credential theft pages and malicious downloads."
                ),
            )
        ],
        threshold=0.30,
    )

    assert match is not None
    assert match.index == 0


def test_topic_duplicate_handles_weak_abstract_with_shared_body_signal() -> None:
    match = find_topic_duplicate(
        "WhatsApp Targeted Again by NSO-linked Phishing Campaign, Meta Says - Haaretz",
        "In the News In the News: Israel-Iran Live Updates Lebanon U.S.-Iran Erdogan.",
        (
            "Meta said WhatsApp users were targeted by NSO-linked spyware operators in a spear phishing "
            "campaign. The one-click phishing attempts were aimed at users in Jordan and Lebanon."
        ),
        [
            (
                "Meta Says Israeli Spyware Firm Targeted WhatsApp Users in Spear-Phishing Campaign - SFist",
                "The article discussed the latest spyware allegations.",
                (
                    "Meta said Israeli spyware firm NSO targeted WhatsApp users in a spear phishing "
                    "campaign. The one-click phishing attempts focused on users in Jordan and Lebanon."
                ),
            )
        ],
        threshold=0.30,
    )

    assert match is not None
    assert match.index == 0


def test_topic_duplicate_requires_salient_title_overlap() -> None:
    match = find_topic_duplicate(
        "Microsoft Teams to add brand impersonation warnings to calls",
        "Microsoft Teams will add warnings for suspicious calls.",
        "Microsoft Teams will warn users about suspicious external calls and impersonation attempts.",
        [
            (
                "Microsoft patches Exchange Server zero-day exploited in attacks",
                "Microsoft released Exchange Server security updates for an exploited vulnerability.",
                "Microsoft released Exchange Server patches for a zero-day vulnerability exploited in attacks.",
            )
        ],
        threshold=0.30,
    )

    assert match is None


def test_topic_duplicate_keeps_separate_vendor_product_launches() -> None:
    match = find_topic_duplicate(
        "KnowBe4 launches game to train staff on vishing scams - SecurityBrief Australia",
        "KnowBe4 launched a gamified vishing training tool for employees.",
        "The training game helps staff identify voice phishing calls and social engineering attempts.",
        [
            (
                "KnowBe4 launches Teams security to tackle chat phishing - SecurityBrief Asia",
                "KnowBe4 launched Microsoft Teams security to detect chat phishing.",
                "The Teams security product detects suspicious messages and phishing attempts in collaboration channels.",
            )
        ],
        threshold=0.30,
    )

    assert match is None

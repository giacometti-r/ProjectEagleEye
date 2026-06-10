from app.detection.attack_classifier import AttackClassifier


def test_detects_phishing_incident() -> None:
    classifier = AttackClassifier()
    result = classifier.classify(
        "Acme Corp attacked in phishing campaign",
        "Attackers targeted Acme Corp and stole credentials from employee inboxes.",
    )
    assert result.article_type == "incident"
    assert result.is_attack
    assert result.attack_type == "phishing"
    assert result.attack_confidence > 0.5
    assert result.incident_confidence > 0.5


def test_classifies_press_release() -> None:
    classifier = AttackClassifier()
    result = classifier.classify(
        "Sublime Security Launches Phishing Defense Channel Partner Program",
        "PRNewswire press release announced the cybersecurity company launch and partner strategy.",
    )
    assert result.article_type == "press_release"
    assert not result.is_attack


def test_flags_out_of_taxonomy_incident() -> None:
    classifier = AttackClassifier()
    result = classifier.classify(
        "Stryker hit by data-wiping attack",
        "Investigators confirmed a wiper incident that disrupted operations at Stryker.",
    )
    assert result.article_type == "incident"
    assert result.attack_type is None
    assert "out-of-taxonomy" in result.reasons


def test_flags_non_cyber_attack_story_out_of_scope() -> None:
    classifier = AttackClassifier()
    result = classifier.classify(
        "Defiant Merkel defends refugee stance after attacks - Digital Journal",
        "The former chancellor defended refugee policy after physical attacks generated political criticism.",
    )
    assert result.article_type == "out_of_scope"
    assert result.attack_type is None
    assert "out-of-scope" in result.reasons


def test_flags_physical_war_attack_story_out_of_scope() -> None:
    classifier = AttackClassifier()
    result = classifier.classify(
        "Russian forces attacked Dnipropetrovsk region, one killed and ten wounded",
        "Officials said artillery attacks damaged homes and wounded civilians.",
    )
    assert result.article_type == "out_of_scope"


def test_classifies_vulnerability_advisory_as_in_scope() -> None:
    classifier = AttackClassifier()
    result = classifier.classify(
        "Google patches new Chrome zero-day flaw exploited in the wild",
        "The security update fixes a vulnerability tracked as CVE-2026-1234.",
    )
    assert result.article_type == "advisory"
    assert result.attack_type is None

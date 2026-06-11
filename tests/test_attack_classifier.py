import pytest

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


@pytest.mark.parametrize(
    ("title", "text"),
    [
        (
            "Sherbrooke police seek help identifying suspect in fraud impersonation case",
            "Police asked the public to identify a suspect after an in-person fraud impersonation case.",
        ),
        (
            "Dorchester Sheriff Investigating Police Impersonation Incident",
            "The sheriff is investigating a police impersonation incident involving a local traffic stop.",
        ),
        (
            "Assam Police Advises Schools Against Sharing Students' Photos Online",
            "Officials said posting student photos online could create privacy and impersonation concerns.",
        ),
        (
            "RAH Infotech partners with 1Kosmos to strengthen identity security across Indian enterprises",
            "The distributor partners with 1Kosmos to strengthen identity security for enterprise customers.",
        ),
        (
            "RAH Infotech adds 1Kosmos to expand identity security portfolio for partners",
            "The company adds 1Kosmos to expand identity security portfolio for channel partners.",
        ),
        (
            "Tuensang DPDB discusses waste management, cybersecurity",
            "The meeting discussed waste management, cybersecurity, public works, and local development.",
        ),
        (
            "Shahdara Dist Police hold mega cyber awareness drive for senior citizens",
            "Police held a cyber awareness drive for senior citizens and reached over 250 residents.",
        ),
        (
            "UPSC Successfully Implements Face Authentication In 2026 Civil Services Prelims, Blocks Impersonation Across",
            "The exam authority used face authentication in civil services prelims and blocked impersonation.",
        ),
        (
            "Krebs on Security - In-depth security news and investigation",
            "A home page listing recent security news and investigation posts.",
        ),
        (
            "How to Recover From a Phishing Scam (2026)",
            "A consumer guide explains basic steps to recover after clicking a phishing link.",
        ),
        (
            "What is malware? How it spreads and how to stay safe",
            "An evergreen explainer describes malware definitions and basic safety practices.",
        ),
    ],
)
def test_digest_false_positives_are_out_of_scope(title: str, text: str) -> None:
    classifier = AttackClassifier()
    result = classifier.classify(title, text)

    assert result.article_type == "out_of_scope"
    assert result.reasons[0].startswith("out-of-scope")


@pytest.mark.parametrize(
    ("title", "text", "expected_attack"),
    [
        (
            "At least $1.7m lost since February to scams where fraudsters impersonate Microsoft tech support",
            "Investigators confirmed victims were targeted by fake Microsoft tech support callers who stole credentials.",
            "impersonation",
        ),
        (
            "Seqrite Warns of Surge in Brand Impersonation Exploiting Customer Trust",
            "Researchers reported a campaign using fake login pages to steal credentials from customers.",
            "impersonation",
        ),
        (
            "Report: Employee Impersonations Hit 53% of Companies Last Year",
            "Researchers reported an employee impersonation campaign that targeted companies through email accounts.",
            "impersonation",
        ),
        (
            "New Phishing Scam Targeting MusicNL Members",
            "Attackers targeted MusicNL members with phishing emails and stole account credentials.",
            "phishing",
        ),
        (
            "Meta Says Israeli Spyware Firm Targeted WhatsApp Users in Spear-Phishing Campaign",
            "Meta said NSO Group targeted WhatsApp users with Pegasus-linked spear phishing attempts.",
            "phishing",
        ),
        (
            "McAfee researchers warn over 100,000 Minecraft players infected by malware",
            "Researchers warned that password-stealing malware infected Minecraft players through mod downloads.",
            None,
        ),
        (
            "Hades PyPI Attack: 19 Packages Poisoned to Auto-Run Bun Credential Stealer",
            "Researchers found malicious PyPI packages that stole credentials from developer machines.",
            "credential theft",
        ),
        (
            "UNC3753 Used Vishing and Physical Intrusions in U.S. Data Theft Extortion Campaign",
            "Researchers reported a vishing campaign where attackers targeted law firms and exfiltrated data.",
            "vishing",
        ),
    ],
)
def test_digest_cyber_items_remain_in_scope(title: str, text: str, expected_attack: str | None) -> None:
    classifier = AttackClassifier()
    result = classifier.classify(title, text)

    assert result.article_type != "out_of_scope"
    assert not result.reasons[0].startswith("out-of-scope")
    assert result.attack_type == expected_attack

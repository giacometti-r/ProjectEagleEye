from __future__ import annotations

import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol


@dataclass(frozen=True)
class AlertEmail:
    subject: str
    body: str


@dataclass(frozen=True)
class DigestEmailItem:
    title: str
    source_name: str
    routing_reason: str
    link: str
    published_date: str
    attack_type: str | None = None
    victim_name: str | None = None


class SmtpClient(Protocol):
    def send_message(self, msg: EmailMessage) -> None:
        ...


class Emailer:
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_username: str,
        smtp_password: str,
        sender_email: str,
        recipient_email: str,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.sender_email = sender_email
        self.recipient_email = recipient_email

    def build_subject(self, victim_name: str, victim_category: str, attack_type: str) -> str:
        victim_name = self._normalize_inline(victim_name, max_chars=120)
        attack_type = self._normalize_inline(attack_type, max_chars=80)
        if victim_category == "company":
            return f"{victim_name} was attacked using {attack_type}"
        return f"[{victim_name}] was attacked using {attack_type}"

    def build_body(
        self,
        abstract: str,
        attack_type: str,
        victim_name: str,
        victim_category: str,
        source_name: str,
        published_date: str,
        link: str,
    ) -> str:
        clean_abstract = self._clean_abstract(abstract)
        return (
            f"Abstract:\n{clean_abstract}\n\n"
            f"Attack type: {attack_type}\n"
            f"Victim: {victim_name}\n"
            f"Victim category: {victim_category}\n"
            f"Source: {source_name}\n"
            f"Published date: {published_date}\n"
            f"Article link: {link}\n"
        )

    def _normalize_inline(self, value: str, max_chars: int) -> str:
        clean = re.sub(r"\s+", " ", value.strip())
        if len(clean) <= max_chars:
            return clean
        clipped = clean[:max_chars]
        last_space = clipped.rfind(" ")
        return clipped if last_space < 20 else clipped[:last_space]

    def _clean_abstract(self, abstract: str) -> str:
        clean = re.sub(r"\s+", " ", abstract.strip())
        if not clean:
            return "No abstract available."
        return clean

    def build_digest_subject(self, item_count: int) -> str:
        return f"Cyber News Digest: {item_count} queued items"

    def build_digest_body(self, items: list[DigestEmailItem]) -> str:
        if not items:
            return "No digest items."

        grouped: dict[str, list[DigestEmailItem]] = {}
        for item in items:
            grouped.setdefault(item.routing_reason, []).append(item)

        lines: list[str] = ["Queued items by reason:", ""]
        for reason in sorted(grouped.keys()):
            lines.append(f"\nReason: {reason} ({len(grouped[reason])})")
            for entry in grouped[reason]:
                attack_type = entry.attack_type or "unknown"
                victim = entry.victim_name or "n/a"
                lines.append(
                    f"\n- {entry.title}\n"
                    f"  Source: {entry.source_name}\n"
                    f"  Attack type: {attack_type}\n"
                    f"  Victim: {victim}\n"
                    f"  Published date: {entry.published_date}\n"
                    f"  Link: {entry.link}"
                )
            lines.append("")
        return "\n".join(lines).strip() + "\n"

    def send(self, email: AlertEmail, recipient_email: str | None = None) -> None:
        message = EmailMessage()
        message["From"] = self.sender_email
        message["To"] = recipient_email or self.recipient_email
        message["Subject"] = email.subject
        message.set_content(email.body)

        tls_context = ssl.create_default_context()
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20) as smtp:
            smtp.starttls(context=tls_context)
            smtp.login(self.smtp_username, self.smtp_password)
            smtp.send_message(message)

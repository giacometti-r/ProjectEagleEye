from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PipelineMetrics:
    processed: int = 0
    alerts_sent: int = 0
    digest_sent: int = 0
    digest_queued: int = 0
    skipped: int = 0
    errors: int = 0

    def add(
        self,
        *,
        processed: int = 0,
        alerts_sent: int = 0,
        digest_sent: int = 0,
        digest_queued: int = 0,
        skipped: int = 0,
        errors: int = 0,
    ) -> PipelineMetrics:
        return PipelineMetrics(
            processed=self.processed + processed,
            alerts_sent=self.alerts_sent + alerts_sent,
            digest_sent=self.digest_sent + digest_sent,
            digest_queued=self.digest_queued + digest_queued,
            skipped=self.skipped + skipped,
            errors=self.errors + errors,
        )

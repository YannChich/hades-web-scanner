"""PDF report export."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.engine import Finding


def generate_pdf(findings: "list[Finding]", url: str, score: int) -> None:
    """Export findings as a PDF report. Implementation coming in a later prompt."""
    pass

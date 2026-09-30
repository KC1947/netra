"""Cross-session server correlation and constraint propagation."""

from .constraints import (
    APPLICABLE_VERSIONS,
    Mode,
    State,
    build_support_matrix,
    deduced_coverage,
    detect_preference_mode,
    find_contradictions,
)
from .cert_association import associate_certificates
from .servers import correlate_servers

__all__ = [
    "APPLICABLE_VERSIONS",
    "Mode",
    "State",
    "associate_certificates",
    "build_support_matrix",
    "correlate_servers",
    "deduced_coverage",
    "detect_preference_mode",
    "find_contradictions",
]

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: str  # dependency, secret, config
    file_path: str = ""
    line_number: int = 0
    remediation: str = ""


@dataclass
class ScanResult:
    repo: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

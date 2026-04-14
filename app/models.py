from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityIssue(BaseModel):
    id: str = Field(..., description="Unique issue identifier, e.g. ISSUE-001")
    title: str = Field(..., description="Short title of the vulnerability")
    severity: Severity = Field(..., description="Issue severity level")
    file: str = Field(..., description="File where the issue was found")
    line_start: Optional[int] = Field(None, description="Starting line number")
    line_end: Optional[int] = Field(None, description="Ending line number")
    description: str = Field(..., description="Detailed description of the vulnerability")
    vulnerable_code: Optional[str] = Field(None, description="The specific vulnerable code snippet")
    fix_suggestion: str = Field(..., description="Concrete fix with example code")
    cwe_id: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-89")


class SecurityReport(BaseModel):
    scan_id: str = Field(..., description="Unique scan identifier (UUID)")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of the scan")
    files_analyzed: List[str] = Field(..., description="List of files that were analyzed")
    total_issues: int = Field(..., description="Total number of issues found")
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    issues: List[SecurityIssue] = Field(..., description="List of all security issues found")
    summary: str = Field(..., description="Overall security assessment summary")


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None

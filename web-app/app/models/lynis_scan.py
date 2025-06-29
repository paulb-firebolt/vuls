"""Lynis scan model for security audits"""

import enum
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base


class LynisScan(Base):
    __tablename__ = "lynis_scans"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)

    # Scan metadata
    scan_date = Column(DateTime(timezone=True))
    hardening_index = Column(Integer)  # 0-100 score from Lynis
    auditor = Column(String, default="Vuls-System")
    lynis_version = Column(String)

    # Scan status tracking
    status = Column(String, default="running")  # running, completed, failed
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)

    # File paths
    remote_report_path = Column(String, default="/var/log/lynis-report.dat")
    local_report_path = Column(String)  # Where we store the downloaded report

    # System information from Lynis
    os_name = Column(String)
    os_version = Column(String)
    kernel_version = Column(String)

    # Summary counts
    total_tests = Column(Integer, default=0)
    total_warnings = Column(Integer, default=0)
    total_suggestions = Column(Integer, default=0)

    # Git information
    git_commit = Column(String)  # Git commit hash of Lynis version used
    git_date = Column(String)    # Date of git commit

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    host = relationship("Host", back_populates="lynis_scans")
    findings = relationship("LynisFinding", back_populates="scan", cascade="all, delete-orphan")

    @property
    def findings_by_type(self):
        """Get findings grouped by type"""
        warnings = [f for f in self.findings if f.finding_type == "WARNING"]
        suggestions = [f for f in self.findings if f.finding_type == "SUGGESTION"]
        return {
            "warnings": warnings,
            "suggestions": suggestions
        }

    @property
    def findings_by_category(self):
        """Get findings grouped by control category"""
        categories = {}
        for finding in self.findings:
            category = finding.control.category if finding.control else "MISC"
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        return categories

    def __repr__(self):
        return f"<LynisScan(id={self.id}, host_id={self.host_id}, status='{self.status}', hardening_index={self.hardening_index})>"

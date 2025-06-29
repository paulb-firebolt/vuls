"""Lynis finding model for security findings and suggestions"""

import enum
from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey, Boolean, UniqueConstraint
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base


class FindingType(str, enum.Enum):
    WARNING = "WARNING"
    SUGGESTION = "SUGGESTION"
    FINDING = "FINDING"


class FindingStatus(str, enum.Enum):
    OK = "OK"
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    SKIPPED = "SKIPPED"


class LynisFinding(Base):
    __tablename__ = "lynis_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("lynis_scans.id"), nullable=False)
    control_id = Column(String, ForeignKey("lynis_controls.control_id"), nullable=False)

    finding_type = Column(Enum(FindingType), nullable=False)
    status = Column(Enum(FindingStatus), nullable=False)
    details = Column(Text)

    # Additional context
    manual_check = Column(Boolean, default=False)
    priority = Column(String)  # high, medium, low

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan = relationship("LynisScan", back_populates="findings")
    control = relationship("LynisControl", back_populates="findings")

    __table_args__ = (
        UniqueConstraint("scan_id", "control_id", "finding_type", name="uq_lynis_finding_scan_control_type"),
    )

    def __repr__(self):
        return f"<LynisFinding(id={self.id}, control_id='{self.control_id}', type='{self.finding_type}', status='{self.status}')>"

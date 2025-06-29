"""Lynis control model for security controls"""

from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base


class LynisControl(Base):
    __tablename__ = "lynis_controls"

    control_id = Column(String, primary_key=True)  # e.g., "AUTH-9262"
    category = Column(String, index=True)  # e.g., "AUTH", "BOOT", "FILE"
    description = Column(Text)
    test_description = Column(Text)

    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    findings = relationship("LynisFinding", back_populates="control")

    def __repr__(self):
        return f"<LynisControl(control_id='{self.control_id}', category='{self.category}')>"

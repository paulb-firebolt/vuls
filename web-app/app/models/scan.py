"""Scan model for vulnerability scans"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)

    # Scan details
    scan_type = Column(String, nullable=False)  # fast, full, custom
    status = Column(String, default="pending")  # pending, running, completed, failed

    # Execution details
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)

    # Results
    vuls_output_path = Column(String)  # Path to Vuls JSON output
    total_packages = Column(Integer)
    total_vulnerabilities = Column(Integer)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Configuration used
    config_snapshot = Column(JSON)  # Snapshot of config.toml used

    # Error handling
    error_message = Column(Text)
    docker_container_id = Column(String)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    host = relationship("Host", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, host_id={self.host_id}, status='{self.status}')>"

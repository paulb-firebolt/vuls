"""Host model for target systems"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from .base import Base


class Host(Base):
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    hostname = Column(String, nullable=False)
    port = Column(Integer, default=22)
    username = Column(String, nullable=True)

    # Connection details
    key_path = Column(String)  # Path to SSH key
    password = Column(String)  # Encrypted password (if used)

    # AWS/GCP proxy settings
    use_aws_proxy = Column(Boolean, default=False)
    aws_instance_id = Column(String)
    aws_region = Column(String)

    use_gcp_proxy = Column(Boolean, default=False)
    gcp_instance_name = Column(String)
    gcp_zone = Column(String)
    gcp_project = Column(String)

    # Scan configuration
    scan_schedule = Column(String)  # Cron expression
    scan_type = Column(String, default="fast")  # fast, full, custom
    scan_mode = Column(String, default="fast")  # Vuls scan mode: fast, offline, etc.
    scan_enabled = Column(Boolean, default=True)

    # Vuls configuration
    vuls_config = Column(JSON)  # Store the original Vuls config for this host

    # Additional configuration
    tags = Column(JSON)  # For grouping and filtering
    description = Column(Text)

    # Status
    is_active = Column(Boolean, default=True)
    last_scan_at = Column(DateTime(timezone=True))
    last_scan_status = Column(String)  # success, failed, running

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    scans = relationship("Scan", back_populates="host", cascade="all, delete-orphan", order_by="Scan.completed_at.desc()")
    lynis_scans = relationship("LynisScan", back_populates="host", cascade="all, delete-orphan", order_by="LynisScan.completed_at.desc()")
    scheduled_tasks = relationship("ScheduledTask", back_populates="host", cascade="all, delete-orphan")

    @property
    def latest_scan(self):
        """Get the most recent completed scan"""
        for scan in self.scans:
            if scan.status == "completed":
                return scan
        return None

    @property
    def latest_lynis_scan(self):
        """Get the most recent completed Lynis scan"""
        for scan in self.lynis_scans:
            if scan.status == "completed":
                return scan
        return None

    @property
    def latest_vulnerabilities(self):
        """Get vulnerabilities from the latest scan"""
        latest = self.latest_scan
        return latest.vulnerabilities if latest else []

    @property
    def latest_lynis_findings(self):
        """Get findings from the latest Lynis scan"""
        latest = self.latest_lynis_scan
        return latest.findings if latest else []

    def __repr__(self):
        return f"<Host(name='{self.name}', hostname='{self.hostname}')>"

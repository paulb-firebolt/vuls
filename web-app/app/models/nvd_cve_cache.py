"""NVD CVE Cache Model"""

from sqlalchemy import Column, Integer, String, Text, Float, DateTime, func, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import text
from .base import Base


class NVDCVECache(Base):
    """Model for caching NVD CVE data in PostgreSQL."""

    __tablename__ = 'nvd_cve_cache'

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)

    # CVSS v3.1 data (preferred)
    cvss_v31_score = Column(Float, nullable=True)
    cvss_v31_vector = Column(String(100), nullable=True)
    cvss_v31_severity = Column(String(20), nullable=True)

    # CVSS v3.0 data (fallback)
    cvss_v30_score = Column(Float, nullable=True)
    cvss_v30_vector = Column(String(100), nullable=True)
    cvss_v30_severity = Column(String(20), nullable=True)

    # CVSS v2 data (legacy fallback)
    cvss_v2_score = Column(Float, nullable=True)
    cvss_v2_vector = Column(String(100), nullable=True)
    cvss_v2_severity = Column(String(20), nullable=True)

    # Metadata
    published_date = Column(DateTime(timezone=True), nullable=True)
    last_modified_date = Column(DateTime(timezone=True), nullable=True)
    source_data = Column(JSONB, nullable=True)  # Store full NVD response for future use

    # Cache management
    cached_at = Column(DateTime(timezone=True), nullable=False)
    last_accessed = Column(DateTime(timezone=True), nullable=False)
    access_count = Column(Integer, nullable=False, default=0)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    # Additional indexes for performance
    __table_args__ = (
        Index('idx_nvd_cve_cache_cve_id', 'cve_id', unique=True),
        Index('idx_nvd_cve_cache_cached_at', 'cached_at'),
        Index('idx_nvd_cve_cache_last_accessed', 'last_accessed'),
        Index('idx_nvd_cve_cache_cvss_score', 'cvss_v31_score', 'cvss_v30_score', 'cvss_v2_score'),
    )

    def __repr__(self):
        return f"<NVDCVECache(cve_id='{self.cve_id}', cvss_score={self.get_best_cvss_score()})>"

    def get_best_cvss_score(self) -> float:
        """Get the best available CVSS score (v3.1 > v3.0 > v2)."""
        if self.cvss_v31_score is not None:
            return self.cvss_v31_score
        elif self.cvss_v30_score is not None:
            return self.cvss_v30_score
        elif self.cvss_v2_score is not None:
            return self.cvss_v2_score
        else:
            return 0.0

    def get_best_cvss_vector(self) -> str:
        """Get the best available CVSS vector string."""
        if self.cvss_v31_vector:
            return self.cvss_v31_vector
        elif self.cvss_v30_vector:
            return self.cvss_v30_vector
        elif self.cvss_v2_vector:
            return self.cvss_v2_vector
        else:
            return ""

    def get_best_severity(self) -> str:
        """Get the best available severity rating."""
        if self.cvss_v31_severity:
            return self.cvss_v31_severity
        elif self.cvss_v30_severity:
            return self.cvss_v30_severity
        elif self.cvss_v2_severity:
            return self.cvss_v2_severity
        else:
            return "Unknown"

    def get_cvss_version_used(self) -> str:
        """Get the CVSS version that was used for the best score."""
        if self.cvss_v31_score is not None:
            return "3.1"
        elif self.cvss_v30_score is not None:
            return "3.0"
        elif self.cvss_v2_score is not None:
            return "2.0"
        else:
            return "None"

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            'cve_id': self.cve_id,
            'description': self.description,
            'cvss_score': self.get_best_cvss_score(),
            'cvss_vector': self.get_best_cvss_vector(),
            'severity': self.get_best_severity(),
            'cvss_version': self.get_cvss_version_used(),
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None,
            'cached_at': self.cached_at.isoformat() if self.cached_at else None,
            'source': 'NVD'
        }

    def update_access_stats(self):
        """Update access statistics."""
        self.last_accessed = func.now()
        self.access_count = self.access_count + 1

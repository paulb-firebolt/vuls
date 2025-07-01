"""Add NVD CVE cache table

Revision ID: add_nvd_cve_cache
Revises: add_debian_oval_schema_tables
Create Date: 2025-07-01 11:09:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_nvd_cve_cache'
down_revision = 'add_debian_oval_schema_tables'
branch_labels = None
depends_on = None


def upgrade():
    # Create NVD CVE cache table
    op.create_table('nvd_cve_cache',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(20), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cvss_v31_score', sa.Float(), nullable=True),
        sa.Column('cvss_v31_vector', sa.String(100), nullable=True),
        sa.Column('cvss_v31_severity', sa.String(20), nullable=True),
        sa.Column('cvss_v30_score', sa.Float(), nullable=True),
        sa.Column('cvss_v30_vector', sa.String(100), nullable=True),
        sa.Column('cvss_v30_severity', sa.String(20), nullable=True),
        sa.Column('cvss_v2_score', sa.Float(), nullable=True),
        sa.Column('cvss_v2_vector', sa.String(100), nullable=True),
        sa.Column('cvss_v2_severity', sa.String(20), nullable=True),
        sa.Column('published_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_modified_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('source_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('cached_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_accessed', sa.DateTime(timezone=True), nullable=False),
        sa.Column('access_count', sa.Integer(), nullable=False, default=0),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # Create unique index on CVE ID for fast lookups
    op.create_index('idx_nvd_cve_cache_cve_id', 'nvd_cve_cache', ['cve_id'], unique=True)

    # Create index on cached_at for cleanup operations
    op.create_index('idx_nvd_cve_cache_cached_at', 'nvd_cve_cache', ['cached_at'])

    # Create index on last_accessed for usage tracking
    op.create_index('idx_nvd_cve_cache_last_accessed', 'nvd_cve_cache', ['last_accessed'])


def downgrade():
    op.drop_index('idx_nvd_cve_cache_last_accessed', table_name='nvd_cve_cache')
    op.drop_index('idx_nvd_cve_cache_cached_at', table_name='nvd_cve_cache')
    op.drop_index('idx_nvd_cve_cache_cve_id', table_name='nvd_cve_cache')
    op.drop_table('nvd_cve_cache')

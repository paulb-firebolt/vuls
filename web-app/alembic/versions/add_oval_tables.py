"""Add OVAL vulnerability database tables

Revision ID: add_oval_tables
Revises: add_security_lookup_tables
Create Date: 2025-06-29 14:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_oval_tables'
down_revision = 'add_security_lookup_tables'
depends_on = None


def upgrade() -> None:
    # Create OVAL definitions table
    op.create_table('ubuntu_oval_definitions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.String(), nullable=False),
        sa.Column('release_version', sa.String(), nullable=False),
        sa.Column('title', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('family', sa.String(), nullable=True),
        sa.Column('class_type', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_updated', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('definition_id', 'release_version', name='uq_oval_def_release')
    )

    # Create indexes for OVAL definitions
    op.create_index('idx_oval_def_id', 'ubuntu_oval_definitions', ['definition_id'])
    op.create_index('idx_oval_release', 'ubuntu_oval_definitions', ['release_version'])
    op.create_index('idx_oval_severity', 'ubuntu_oval_definitions', ['severity'])

    # Create OVAL packages table
    op.create_table('ubuntu_oval_packages',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.Integer(), sa.ForeignKey('ubuntu_oval_definitions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('package_name', sa.String(), nullable=False),
        sa.Column('version', sa.String(), nullable=True),
        sa.Column('architecture', sa.String(), nullable=True),
        sa.Column('not_fixed_yet', sa.Boolean(), default=False, nullable=False),
        sa.Column('modularity_label', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for OVAL packages
    op.create_index('idx_oval_pkg_name', 'ubuntu_oval_packages', ['package_name'])
    op.create_index('idx_oval_pkg_def', 'ubuntu_oval_packages', ['definition_id'])
    op.create_index('idx_oval_pkg_name_def', 'ubuntu_oval_packages', ['package_name', 'definition_id'])

    # Create OVAL references table (CVEs, USNs, etc.)
    op.create_table('ubuntu_oval_references',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.Integer(), sa.ForeignKey('ubuntu_oval_definitions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('ref_id', sa.String(), nullable=False),
        sa.Column('ref_url', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for OVAL references
    op.create_index('idx_oval_ref_def', 'ubuntu_oval_references', ['definition_id'])
    op.create_index('idx_oval_ref_id', 'ubuntu_oval_references', ['ref_id'])
    op.create_index('idx_oval_ref_source', 'ubuntu_oval_references', ['source'])

    # Create OVAL advisories table
    op.create_table('ubuntu_oval_advisories',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.Integer(), sa.ForeignKey('ubuntu_oval_definitions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('severity', sa.String(), nullable=True),
        sa.Column('affected_repository', sa.String(), nullable=True),
        sa.Column('issued', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for OVAL advisories
    op.create_index('idx_oval_adv_def', 'ubuntu_oval_advisories', ['definition_id'])
    op.create_index('idx_oval_adv_severity', 'ubuntu_oval_advisories', ['severity'])
    op.create_index('idx_oval_adv_issued', 'ubuntu_oval_advisories', ['issued'])

    # Create OVAL CVEs table
    op.create_table('ubuntu_oval_cves',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('advisory_id', sa.Integer(), sa.ForeignKey('ubuntu_oval_advisories.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cve_id', sa.String(), nullable=False),
        sa.Column('cvss2', sa.String(), nullable=True),
        sa.Column('cvss3', sa.String(), nullable=True),
        sa.Column('cwe', sa.String(), nullable=True),
        sa.Column('impact', sa.String(), nullable=True),
        sa.Column('href', sa.String(), nullable=True),
        sa.Column('public', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for OVAL CVEs
    op.create_index('idx_oval_cve_adv', 'ubuntu_oval_cves', ['advisory_id'])
    op.create_index('idx_oval_cve_id', 'ubuntu_oval_cves', ['cve_id'])

    # Create OVAL metadata table
    op.create_table('ubuntu_oval_meta',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('release_version', sa.String(), nullable=False),
        sa.Column('last_download', sa.DateTime(timezone=True), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('definitions_count', sa.Integer(), nullable=True),
        sa.Column('packages_count', sa.Integer(), nullable=True),
        sa.Column('cves_count', sa.Integer(), nullable=True),
        sa.Column('download_url', sa.Text(), nullable=True),
        sa.Column('file_timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('release_version', name='uq_oval_meta_release')
    )

    # Create indexes for OVAL metadata
    op.create_index('idx_oval_meta_release', 'ubuntu_oval_meta', ['release_version'])
    op.create_index('idx_oval_meta_download', 'ubuntu_oval_meta', ['last_download'])

    # Create vulnerability data sources tracking table
    op.create_table('vulnerability_data_sources',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(), nullable=False),
        sa.Column('package_name', sa.String(), nullable=False),
        sa.Column('release_name', sa.String(), nullable=False),
        sa.Column('source_type', sa.String(), nullable=False),  # 'USN', 'OVAL', etc.
        sa.Column('source_name', sa.String(), nullable=False),  # 'ubuntu_usn', 'ubuntu_oval', etc.
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('last_updated', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for vulnerability data sources
    op.create_index('idx_vuln_src_cve_pkg', 'vulnerability_data_sources', ['cve_id', 'package_name'])
    op.create_index('idx_vuln_src_type', 'vulnerability_data_sources', ['source_type'])
    op.create_index('idx_vuln_src_name', 'vulnerability_data_sources', ['source_name'])

    # Create a unified view that combines USN and OVAL data
    op.execute("""
        CREATE VIEW unified_ubuntu_vulnerabilities AS
        SELECT
            'USN' as source_type,
            'ubuntu_usn' as source_name,
            cve_id,
            package_name,
            release_name,
            status,
            fixed_version,
            priority as severity,
            usn_id as reference_id,
            description,
            last_updated,
            0.95 as confidence_score
        FROM ubuntu_security_data

        UNION ALL

        SELECT
            'OVAL' as source_type,
            'ubuntu_oval' as source_name,
            r.ref_id as cve_id,
            p.package_name,
            d.release_version as release_name,
            CASE
                WHEN p.not_fixed_yet THEN 'needs-triage'
                WHEN p.version IS NOT NULL THEN 'released'
                ELSE 'unknown'
            END as status,
            p.version as fixed_version,
            d.severity,
            d.definition_id as reference_id,
            d.description,
            d.last_updated,
            0.90 as confidence_score
        FROM ubuntu_oval_definitions d
        JOIN ubuntu_oval_packages p ON d.id = p.definition_id
        JOIN ubuntu_oval_references r ON d.id = r.definition_id
        WHERE r.source = 'CVE' AND r.ref_id LIKE 'CVE-%'
    """)


def downgrade() -> None:
    # Drop the unified view first
    op.execute("DROP VIEW IF EXISTS unified_ubuntu_vulnerabilities")

    # Drop tables in reverse order
    op.drop_table('vulnerability_data_sources')
    op.drop_table('ubuntu_oval_meta')
    op.drop_table('ubuntu_oval_cves')
    op.drop_table('ubuntu_oval_advisories')
    op.drop_table('ubuntu_oval_references')
    op.drop_table('ubuntu_oval_packages')
    op.drop_table('ubuntu_oval_definitions')

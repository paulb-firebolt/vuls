"""Add Debian OVAL tables

Revision ID: cac29aabed3f
Revises: 923c9d2b9855
Create Date: 2025-06-30 09:35:53.191158

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cac29aabed3f'
down_revision: Union[str, Sequence[str], None] = '923c9d2b9855'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create Debian OVAL definitions table
    op.create_table(
        'debian_oval_definitions',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('definition_id', sa.String(255), nullable=False),
        sa.Column('release_version', sa.String(50), nullable=False),
        sa.Column('title', sa.Text),
        sa.Column('description', sa.Text),
        sa.Column('severity', sa.String(50)),
        sa.Column('family', sa.String(100)),
        sa.Column('class_type', sa.String(100)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Create indexes for Debian OVAL definitions
    op.create_index('ix_debian_oval_definitions_definition_id', 'debian_oval_definitions', ['definition_id'])
    op.create_index('ix_debian_oval_definitions_release_version', 'debian_oval_definitions', ['release_version'])
    op.create_index('ix_debian_oval_definitions_severity', 'debian_oval_definitions', ['severity'])
    op.create_unique_constraint('uq_debian_oval_definitions_def_release', 'debian_oval_definitions', ['definition_id', 'release_version'])

    # Create Debian OVAL packages table
    op.create_table(
        'debian_oval_packages',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('definition_id', sa.Integer, sa.ForeignKey('debian_oval_definitions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('package_name', sa.String(255), nullable=False),
        sa.Column('version', sa.String(255)),
        sa.Column('architecture', sa.String(50)),
        sa.Column('not_fixed_yet', sa.Boolean, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Create indexes for Debian OVAL packages
    op.create_index('ix_debian_oval_packages_definition_id', 'debian_oval_packages', ['definition_id'])
    op.create_index('ix_debian_oval_packages_package_name', 'debian_oval_packages', ['package_name'])

    # Create Debian OVAL references table
    op.create_table(
        'debian_oval_references',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('definition_id', sa.Integer, sa.ForeignKey('debian_oval_definitions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', sa.String(100)),
        sa.Column('ref_id', sa.String(255), nullable=False),
        sa.Column('ref_url', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Create indexes for Debian OVAL references
    op.create_index('ix_debian_oval_references_definition_id', 'debian_oval_references', ['definition_id'])
    op.create_index('ix_debian_oval_references_ref_id', 'debian_oval_references', ['ref_id'])
    op.create_index('ix_debian_oval_references_source', 'debian_oval_references', ['source'])

    # Create Debian OVAL advisories table
    op.create_table(
        'debian_oval_advisories',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('definition_id', sa.Integer, sa.ForeignKey('debian_oval_definitions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('severity', sa.String(50)),
        sa.Column('issued', sa.DateTime(timezone=True)),
        sa.Column('updated', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Create indexes for Debian OVAL advisories
    op.create_index('ix_debian_oval_advisories_definition_id', 'debian_oval_advisories', ['definition_id'])
    op.create_index('ix_debian_oval_advisories_severity', 'debian_oval_advisories', ['severity'])
    op.create_index('ix_debian_oval_advisories_issued', 'debian_oval_advisories', ['issued'])

    # Create Debian OVAL CVEs table
    op.create_table(
        'debian_oval_cves',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('definition_id', sa.Integer, sa.ForeignKey('debian_oval_definitions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cve_id', sa.String(50), nullable=False),
        sa.Column('cvss_score', sa.Float),
        sa.Column('cvss_vector', sa.String(255)),
        sa.Column('description', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Create indexes for Debian OVAL CVEs
    op.create_index('ix_debian_oval_cves_definition_id', 'debian_oval_cves', ['definition_id'])
    op.create_index('ix_debian_oval_cves_cve_id', 'debian_oval_cves', ['cve_id'])
    op.create_index('ix_debian_oval_cves_cvss_score', 'debian_oval_cves', ['cvss_score'])

    # Create Debian OVAL metadata table
    op.create_table(
        'debian_oval_meta',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('release_version', sa.String(50), nullable=False, unique=True),
        sa.Column('last_download', sa.DateTime(timezone=True)),
        sa.Column('file_size', sa.BigInteger),
        sa.Column('definitions_count', sa.Integer, default=0),
        sa.Column('packages_count', sa.Integer, default=0),
        sa.Column('cves_count', sa.Integer, default=0),
        sa.Column('download_url', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Create indexes for Debian OVAL metadata
    op.create_index('ix_debian_oval_meta_release_version', 'debian_oval_meta', ['release_version'])
    op.create_index('ix_debian_oval_meta_last_download', 'debian_oval_meta', ['last_download'])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop tables in reverse order
    op.drop_table('debian_oval_meta')
    op.drop_table('debian_oval_cves')
    op.drop_table('debian_oval_advisories')
    op.drop_table('debian_oval_references')
    op.drop_table('debian_oval_packages')
    op.drop_table('debian_oval_definitions')

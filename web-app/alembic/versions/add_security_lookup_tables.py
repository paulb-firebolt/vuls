"""Add Ubuntu and Debian security lookup tables

Revision ID: add_security_lookup_tables
Revises:
Create Date: 2025-06-29 14:06:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_security_lookup_tables'
down_revision = None
depends_on = None


def upgrade() -> None:
    # Create Ubuntu security data table
    op.create_table('ubuntu_security_data',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(), nullable=False),
        sa.Column('package_name', sa.String(), nullable=False),
        sa.Column('release_name', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('fixed_version', sa.String(), nullable=True),
        sa.Column('priority', sa.String(), nullable=True),
        sa.Column('usn_id', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('last_updated', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cve_id', 'package_name', 'release_name', name='uq_ubuntu_cve_package_release')
    )

    # Create indexes for Ubuntu security data
    op.create_index('idx_ubuntu_cve_package', 'ubuntu_security_data', ['cve_id', 'package_name'])
    op.create_index('idx_ubuntu_package_release', 'ubuntu_security_data', ['package_name', 'release_name'])

    # Create Ubuntu data metadata table
    op.create_table('ubuntu_data_meta',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('last_download', sa.DateTime(timezone=True), nullable=True),
        sa.Column('data_size', sa.Integer(), nullable=True),
        sa.Column('usn_count', sa.Integer(), nullable=True),
        sa.Column('cve_count', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Create Debian security data table
    op.create_table('debian_security_data',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('cve_id', sa.String(), nullable=False),
        sa.Column('package_name', sa.String(), nullable=False),
        sa.Column('release_name', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('fixed_version', sa.String(), nullable=True),
        sa.Column('urgency', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('last_updated', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cve_id', 'package_name', 'release_name', name='uq_debian_cve_package_release')
    )

    # Create indexes for Debian security data
    op.create_index('idx_debian_cve_package', 'debian_security_data', ['cve_id', 'package_name'])
    op.create_index('idx_debian_package_release', 'debian_security_data', ['package_name', 'release_name'])

    # Create Debian data metadata table
    op.create_table('debian_data_meta',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('last_download', sa.DateTime(timezone=True), nullable=True),
        sa.Column('data_size', sa.Integer(), nullable=True),
        sa.Column('cve_count', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    # Drop tables in reverse order
    op.drop_table('debian_data_meta')
    op.drop_table('debian_security_data')
    op.drop_table('ubuntu_data_meta')
    op.drop_table('ubuntu_security_data')

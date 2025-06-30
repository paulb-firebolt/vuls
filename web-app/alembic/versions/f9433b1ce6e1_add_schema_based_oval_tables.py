"""add_schema_based_oval_tables

Revision ID: f9433b1ce6e1
Revises: cac29aabed3f
Create Date: 2025-06-30 13:44:32.679150

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f9433b1ce6e1'
down_revision: Union[str, Sequence[str], None] = 'cac29aabed3f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create OVAL Schema Definitions table (main patch definitions)
    op.create_table(
        'oval_schema_definitions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.String(255), nullable=False),
        sa.Column('release_version', sa.String(10), nullable=False),
        sa.Column('title', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(50), nullable=True),
        sa.Column('family', sa.String(50), nullable=True),
        sa.Column('class_type', sa.String(20), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('definition_id')
    )

    # Create OVAL Schema Tests table (dpkginfo_test elements)
    op.create_table(
        'oval_schema_tests',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('test_id', sa.String(255), nullable=False),
        sa.Column('test_type', sa.String(50), nullable=False),
        sa.Column('check_existence', sa.String(50), nullable=True),
        sa.Column('check_operation', sa.String(20), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('object_ref', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('test_id')
    )

    # Create OVAL Schema Objects table (package references)
    op.create_table(
        'oval_schema_objects',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('object_id', sa.String(255), nullable=False),
        sa.Column('object_type', sa.String(50), nullable=False),
        sa.Column('package_name', sa.String(255), nullable=True),
        sa.Column('architecture', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('object_id')
    )

    # Create OVAL Schema States table (version constraints)
    op.create_table(
        'oval_schema_states',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('state_id', sa.String(255), nullable=False),
        sa.Column('state_type', sa.String(50), nullable=False),
        sa.Column('package_name', sa.String(255), nullable=True),
        sa.Column('evr_operation', sa.String(20), nullable=True),
        sa.Column('evr_value', sa.String(255), nullable=True),
        sa.Column('arch_operation', sa.String(20), nullable=True),
        sa.Column('arch_value', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('state_id')
    )

    # Create OVAL Schema Criteria table (logic trees)
    op.create_table(
        'oval_schema_criteria',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.Integer(), nullable=False),
        sa.Column('parent_id', sa.Integer(), nullable=True),
        sa.Column('operator', sa.String(10), nullable=False),
        sa.Column('test_ref', sa.String(255), nullable=True),
        sa.Column('extend_definition_ref', sa.String(255), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['definition_id'], ['oval_schema_definitions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['parent_id'], ['oval_schema_criteria.id'], ondelete='CASCADE')
    )

    # Create OVAL Schema References table (CVE/USN mappings)
    op.create_table(
        'oval_schema_references',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(50), nullable=True),
        sa.Column('ref_id', sa.String(100), nullable=False),
        sa.Column('ref_url', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('NOW()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['definition_id'], ['oval_schema_definitions.id'], ondelete='CASCADE')
    )

    # Create OVAL Schema Test-State relationships (many-to-many)
    op.create_table(
        'oval_schema_test_states',
        sa.Column('test_id', sa.Integer(), nullable=False),
        sa.Column('state_id', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('test_id', 'state_id'),
        sa.ForeignKeyConstraint(['test_id'], ['oval_schema_tests.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['state_id'], ['oval_schema_states.id'], ondelete='CASCADE')
    )

    # Create indexes for performance
    op.create_index('idx_oval_schema_definitions_definition_id', 'oval_schema_definitions', ['definition_id'])
    op.create_index('idx_oval_schema_definitions_release', 'oval_schema_definitions', ['release_version'])
    op.create_index('idx_oval_schema_definitions_class_type', 'oval_schema_definitions', ['class_type'])

    op.create_index('idx_oval_schema_tests_test_id', 'oval_schema_tests', ['test_id'])
    op.create_index('idx_oval_schema_tests_object_ref', 'oval_schema_tests', ['object_ref'])

    op.create_index('idx_oval_schema_objects_object_id', 'oval_schema_objects', ['object_id'])
    op.create_index('idx_oval_schema_objects_package_name', 'oval_schema_objects', ['package_name'])

    op.create_index('idx_oval_schema_states_state_id', 'oval_schema_states', ['state_id'])
    op.create_index('idx_oval_schema_states_package_name', 'oval_schema_states', ['package_name'])
    op.create_index('idx_oval_schema_states_evr_operation', 'oval_schema_states', ['evr_operation'])

    op.create_index('idx_oval_schema_criteria_definition_id', 'oval_schema_criteria', ['definition_id'])
    op.create_index('idx_oval_schema_criteria_parent_id', 'oval_schema_criteria', ['parent_id'])
    op.create_index('idx_oval_schema_criteria_test_ref', 'oval_schema_criteria', ['test_ref'])

    op.create_index('idx_oval_schema_references_definition_id', 'oval_schema_references', ['definition_id'])
    op.create_index('idx_oval_schema_references_ref_id', 'oval_schema_references', ['ref_id'])
    op.create_index('idx_oval_schema_references_source', 'oval_schema_references', ['source'])

    # Create composite indexes for common queries
    op.create_index('idx_oval_schema_refs_cve_lookup', 'oval_schema_references', ['ref_id', 'source'])
    op.create_index('idx_oval_schema_objects_pkg_arch', 'oval_schema_objects', ['package_name', 'architecture'])
    op.create_index('idx_oval_schema_states_pkg_evr', 'oval_schema_states', ['package_name', 'evr_operation'])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes first
    op.drop_index('idx_oval_schema_states_pkg_evr')
    op.drop_index('idx_oval_schema_objects_pkg_arch')
    op.drop_index('idx_oval_schema_refs_cve_lookup')

    op.drop_index('idx_oval_schema_references_source')
    op.drop_index('idx_oval_schema_references_ref_id')
    op.drop_index('idx_oval_schema_references_definition_id')

    op.drop_index('idx_oval_schema_criteria_test_ref')
    op.drop_index('idx_oval_schema_criteria_parent_id')
    op.drop_index('idx_oval_schema_criteria_definition_id')

    op.drop_index('idx_oval_schema_states_evr_operation')
    op.drop_index('idx_oval_schema_states_package_name')
    op.drop_index('idx_oval_schema_states_state_id')

    op.drop_index('idx_oval_schema_objects_package_name')
    op.drop_index('idx_oval_schema_objects_object_id')

    op.drop_index('idx_oval_schema_tests_object_ref')
    op.drop_index('idx_oval_schema_tests_test_id')

    op.drop_index('idx_oval_schema_definitions_class_type')
    op.drop_index('idx_oval_schema_definitions_release')
    op.drop_index('idx_oval_schema_definitions_definition_id')

    # Drop tables in reverse order (respecting foreign key constraints)
    op.drop_table('oval_schema_test_states')
    op.drop_table('oval_schema_references')
    op.drop_table('oval_schema_criteria')
    op.drop_table('oval_schema_states')
    op.drop_table('oval_schema_objects')
    op.drop_table('oval_schema_tests')
    op.drop_table('oval_schema_definitions')

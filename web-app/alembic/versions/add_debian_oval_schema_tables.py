"""add_debian_oval_schema_tables

Revision ID: add_debian_oval_schema_tables
Revises: add_variable_ref_to_objects
Create Date: 2025-06-30 17:35:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'add_debian_oval_schema_tables'
down_revision: Union[str, Sequence[str], None] = 'add_variable_ref_to_objects'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add Debian OVAL schema tables."""

    # Create debian_oval_schema_definitions table
    op.create_table('debian_oval_schema_definitions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.String(length=255), nullable=False),
        sa.Column('release_version', sa.String(length=50), nullable=False),
        sa.Column('title', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=True),
        sa.Column('family', sa.String(length=100), nullable=True),
        sa.Column('class_type', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('definition_id', 'release_version')
    )
    op.create_index('ix_debian_oval_schema_definitions_definition_id', 'debian_oval_schema_definitions', ['definition_id'])
    op.create_index('ix_debian_oval_schema_definitions_release_version', 'debian_oval_schema_definitions', ['release_version'])

    # Create debian_oval_schema_tests table
    op.create_table('debian_oval_schema_tests',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('test_id', sa.String(length=255), nullable=False),
        sa.Column('test_type', sa.String(length=100), nullable=False),
        sa.Column('check_existence', sa.String(length=50), nullable=True),
        sa.Column('check_operation', sa.String(length=50), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('object_ref', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('test_id')
    )
    op.create_index('ix_debian_oval_schema_tests_test_id', 'debian_oval_schema_tests', ['test_id'])
    op.create_index('ix_debian_oval_schema_tests_object_ref', 'debian_oval_schema_tests', ['object_ref'])

    # Create debian_oval_schema_objects table
    op.create_table('debian_oval_schema_objects',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('object_id', sa.String(length=255), nullable=False),
        sa.Column('object_type', sa.String(length=100), nullable=False),
        sa.Column('package_name', sa.String(length=255), nullable=True),
        sa.Column('architecture', sa.String(length=50), nullable=True),
        sa.Column('variable_ref', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('object_id')
    )
    op.create_index('ix_debian_oval_schema_objects_object_id', 'debian_oval_schema_objects', ['object_id'])
    op.create_index('ix_debian_oval_schema_objects_package_name', 'debian_oval_schema_objects', ['package_name'])
    op.create_index('ix_debian_oval_schema_objects_variable_ref', 'debian_oval_schema_objects', ['variable_ref'])

    # Create debian_oval_schema_states table
    op.create_table('debian_oval_schema_states',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('state_id', sa.String(length=255), nullable=False),
        sa.Column('state_type', sa.String(length=100), nullable=False),
        sa.Column('package_name', sa.String(length=255), nullable=True),
        sa.Column('evr_operation', sa.String(length=50), nullable=True),
        sa.Column('evr_value', sa.String(length=255), nullable=True),
        sa.Column('arch_operation', sa.String(length=50), nullable=True),
        sa.Column('arch_value', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('state_id')
    )
    op.create_index('ix_debian_oval_schema_states_state_id', 'debian_oval_schema_states', ['state_id'])
    op.create_index('ix_debian_oval_schema_states_package_name', 'debian_oval_schema_states', ['package_name'])
    op.create_index('ix_debian_oval_schema_states_evr_operation', 'debian_oval_schema_states', ['evr_operation'])

    # Create debian_oval_schema_criteria table
    op.create_table('debian_oval_schema_criteria',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.Integer(), nullable=False),
        sa.Column('parent_id', sa.Integer(), nullable=True),
        sa.Column('operator', sa.String(length=20), nullable=False),
        sa.Column('test_ref', sa.String(length=255), nullable=True),
        sa.Column('extend_definition_ref', sa.String(length=255), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['definition_id'], ['debian_oval_schema_definitions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['parent_id'], ['debian_oval_schema_criteria.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_debian_oval_schema_criteria_definition_id', 'debian_oval_schema_criteria', ['definition_id'])
    op.create_index('ix_debian_oval_schema_criteria_parent_id', 'debian_oval_schema_criteria', ['parent_id'])
    op.create_index('ix_debian_oval_schema_criteria_test_ref', 'debian_oval_schema_criteria', ['test_ref'])

    # Create debian_oval_schema_references table
    op.create_table('debian_oval_schema_references',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('definition_id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=True),
        sa.Column('ref_id', sa.String(length=255), nullable=False),
        sa.Column('ref_url', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['definition_id'], ['debian_oval_schema_definitions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_debian_oval_schema_references_definition_id', 'debian_oval_schema_references', ['definition_id'])
    op.create_index('ix_debian_oval_schema_references_ref_id', 'debian_oval_schema_references', ['ref_id'])
    op.create_index('ix_debian_oval_schema_references_source', 'debian_oval_schema_references', ['source'])

    # Create debian_oval_schema_test_states table
    op.create_table('debian_oval_schema_test_states',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('test_id', sa.Integer(), nullable=False),
        sa.Column('state_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['test_id'], ['debian_oval_schema_tests.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['state_id'], ['debian_oval_schema_states.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('test_id', 'state_id')
    )
    op.create_index('ix_debian_oval_schema_test_states_test_id', 'debian_oval_schema_test_states', ['test_id'])
    op.create_index('ix_debian_oval_schema_test_states_state_id', 'debian_oval_schema_test_states', ['state_id'])

    # Create debian_oval_schema_variables table
    op.create_table('debian_oval_schema_variables',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('variable_id', sa.String(length=255), nullable=False),
        sa.Column('variable_type', sa.String(length=100), nullable=False),
        sa.Column('datatype', sa.String(length=50), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('variable_id')
    )
    op.create_index('ix_debian_oval_schema_variables_variable_id', 'debian_oval_schema_variables', ['variable_id'])

    # Create debian_oval_schema_variable_values table
    op.create_table('debian_oval_schema_variable_values',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('variable_id', sa.Integer(), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['variable_id'], ['debian_oval_schema_variables.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_debian_oval_schema_variable_values_variable_id', 'debian_oval_schema_variable_values', ['variable_id'])
    op.create_index('ix_debian_oval_schema_variable_values_value', 'debian_oval_schema_variable_values', ['value'])


def downgrade() -> None:
    """Remove Debian OVAL schema tables."""

    # Drop tables in reverse order due to foreign key constraints
    op.drop_table('debian_oval_schema_variable_values')
    op.drop_table('debian_oval_schema_variables')
    op.drop_table('debian_oval_schema_test_states')
    op.drop_table('debian_oval_schema_references')
    op.drop_table('debian_oval_schema_criteria')
    op.drop_table('debian_oval_schema_states')
    op.drop_table('debian_oval_schema_objects')
    op.drop_table('debian_oval_schema_tests')
    op.drop_table('debian_oval_schema_definitions')

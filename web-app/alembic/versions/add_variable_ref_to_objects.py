"""Add variable_ref column to oval_schema_objects

Revision ID: add_variable_ref_to_objects
Revises: add_oval_variables
Create Date: 2025-06-30 16:03:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_variable_ref_to_objects'
down_revision = 'add_oval_variables'
branch_labels = None
depends_on = None


def upgrade():
    # Add variable_ref column to oval_schema_objects table
    op.add_column('oval_schema_objects', sa.Column('variable_ref', sa.String(255), nullable=True))


def downgrade():
    # Remove variable_ref column from oval_schema_objects table
    op.drop_column('oval_schema_objects', 'variable_ref')

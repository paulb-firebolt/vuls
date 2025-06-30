"""Add OVAL variables tables

Revision ID: add_oval_variables
Revises: f9433b1ce6e1
Create Date: 2025-06-30 15:57:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_oval_variables'
down_revision = 'f9433b1ce6e1'
branch_labels = None
depends_on = None


def upgrade():
    # Create OVAL variables table
    op.create_table('oval_schema_variables',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('variable_id', sa.String(255), nullable=False),
        sa.Column('variable_type', sa.String(50), nullable=False),
        sa.Column('datatype', sa.String(50), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('variable_id')
    )

    # Create OVAL variable values table (for multiple values per variable)
    op.create_table('oval_schema_variable_values',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('variable_id', sa.Integer(), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['variable_id'], ['oval_schema_variables.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for performance
    op.create_index('idx_oval_variables_variable_id', 'oval_schema_variables', ['variable_id'])
    op.create_index('idx_oval_variable_values_variable_id', 'oval_schema_variable_values', ['variable_id'])
    op.create_index('idx_oval_variable_values_value', 'oval_schema_variable_values', ['value'])


def downgrade():
    op.drop_index('idx_oval_variable_values_value', table_name='oval_schema_variable_values')
    op.drop_index('idx_oval_variable_values_variable_id', table_name='oval_schema_variable_values')
    op.drop_index('idx_oval_variables_variable_id', table_name='oval_schema_variables')
    op.drop_table('oval_schema_variable_values')
    op.drop_table('oval_schema_variables')

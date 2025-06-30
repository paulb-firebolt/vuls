"""Add Debian OVAL tables

Revision ID: 923c9d2b9855
Revises: d9add222d037
Create Date: 2025-06-30 10:35:29.951789

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '923c9d2b9855'
down_revision: Union[str, Sequence[str], None] = 'd9add222d037'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass

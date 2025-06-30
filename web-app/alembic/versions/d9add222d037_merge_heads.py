"""merge heads

Revision ID: d9add222d037
Revises: add_oval_tables, f168cb5dc958
Create Date: 2025-06-29 13:56:38.249970

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd9add222d037'
down_revision: Union[str, Sequence[str], None] = ('add_oval_tables', 'f168cb5dc958')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass

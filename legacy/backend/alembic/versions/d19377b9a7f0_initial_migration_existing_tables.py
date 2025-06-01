"""Initial migration - existing tables

Revision ID: d19377b9a7f0
Revises: 
Create Date: 2025-07-07 16:12:47.805201

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd19377b9a7f0'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Tables already exist in the database, so we don't create them
    # This migration serves as the baseline for future migrations
    # The following tables already exist:
    # - search_cache
    # - schema_migrations
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass

"""add case alerts table

Revision ID: c7e2d94a1b05
Revises: b1218046b63f
Create Date: 2026-09-25 15:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c7e2d94a1b05'
down_revision: Union[str, Sequence[str], None] = 'b1218046b63f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'case_alerts',
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('case_id', 'alert_id'),
    )
    op.create_index(op.f('ix_case_alerts_alert_id'), 'case_alerts', ['alert_id'], unique=False)
    op.create_index(op.f('ix_case_alerts_case_id'), 'case_alerts', ['case_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_case_alerts_case_id'), table_name='case_alerts')
    op.drop_index(op.f('ix_case_alerts_alert_id'), table_name='case_alerts')
    op.drop_table('case_alerts')

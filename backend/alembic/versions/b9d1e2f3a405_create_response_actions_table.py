"""create response actions table for active response containment

Revision ID: b9d1e2f3a405
Revises: a8c9d1e2f304
Create Date: 2026-09-26 01:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b9d1e2f3a405'
down_revision: Union[str, Sequence[str], None] = 'a8c9d1e2f304'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: create response_actions table and indexes."""
    op.create_table(
        'response_actions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=True),
        sa.Column('alert_id', sa.Integer(), nullable=True),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('command', sa.String(length=128), nullable=False),
        sa.Column('target_type', sa.String(length=32), nullable=False),
        sa.Column('target_value', sa.String(length=255), nullable=False),
        sa.Column(
            'parameters',
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column('status', sa.String(length=32), server_default='pending', nullable=False),
        sa.Column('execution_output', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('executed_by_id', sa.Integer(), nullable=True),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['executed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_index(op.f('ix_response_actions_case_id'), 'response_actions', ['case_id'], unique=False)
    op.create_index(op.f('ix_response_actions_alert_id'), 'response_actions', ['alert_id'], unique=False)
    op.create_index(op.f('ix_response_actions_status'), 'response_actions', ['status'], unique=False)
    op.create_index(op.f('ix_response_actions_target_value'), 'response_actions', ['target_value'], unique=False)
    op.create_index(op.f('ix_response_actions_created_at'), 'response_actions', [sa.text('created_at DESC')], unique=False)


def downgrade() -> None:
    """Downgrade schema: drop response_actions table and indexes."""
    op.drop_index(op.f('ix_response_actions_created_at'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_target_value'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_status'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_alert_id'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_case_id'), table_name='response_actions')
    op.drop_table('response_actions')

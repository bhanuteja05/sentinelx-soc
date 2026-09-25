"""add case evidence table and lifecycle fields to cases

Revision ID: a8c9d1e2f304
Revises: f3b5c719e204
Create Date: 2026-09-26 00:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a8c9d1e2f304'
down_revision: Union[str, Sequence[str], None] = 'f3b5c719e204'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: add lifecycle fields to cases and create case_evidence table."""
    # 1. Add lifecycle and ownership columns to cases table
    op.add_column(
        'cases',
        sa.Column(
            'assignee_id',
            sa.Integer(),
            sa.ForeignKey('users.id', ondelete='SET NULL'),
            nullable=True,
        ),
    )
    op.add_column('cases', sa.Column('disposition', sa.String(length=64), nullable=True))
    op.add_column('cases', sa.Column('root_cause', sa.String(length=64), nullable=True))
    op.add_column('cases', sa.Column('resolution_summary', sa.Text(), nullable=True))
    op.add_column('cases', sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'cases',
        sa.Column(
            'resolved_by_id',
            sa.Integer(),
            sa.ForeignKey('users.id', ondelete='SET NULL'),
            nullable=True,
        ),
    )

    op.create_index(op.f('ix_cases_assignee_id'), 'cases', ['assignee_id'], unique=False)
    op.create_index(op.f('ix_cases_disposition'), 'cases', ['disposition'], unique=False)

    # 2. Create case_evidence table
    op.create_table(
        'case_evidence',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('alert_id', sa.Integer(), nullable=True),
        sa.Column('evidence_type', sa.String(length=32), nullable=False),
        sa.Column('value', sa.String(length=512), nullable=False),
        sa.Column('verdict', sa.String(length=32), server_default='suspicious', nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('added_by_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['added_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_case_evidence_case_id'), 'case_evidence', ['case_id'], unique=False)
    op.create_index(op.f('ix_case_evidence_alert_id'), 'case_evidence', ['alert_id'], unique=False)
    op.create_index(op.f('ix_case_evidence_evidence_type'), 'case_evidence', ['evidence_type'], unique=False)
    op.create_index(op.f('ix_case_evidence_value'), 'case_evidence', ['value'], unique=False)
    op.create_index(op.f('ix_case_evidence_verdict'), 'case_evidence', ['verdict'], unique=False)


def downgrade() -> None:
    """Downgrade schema: drop case_evidence table and remove lifecycle columns from cases."""
    # 1. Drop case_evidence table and its indexes
    op.drop_index(op.f('ix_case_evidence_verdict'), table_name='case_evidence')
    op.drop_index(op.f('ix_case_evidence_value'), table_name='case_evidence')
    op.drop_index(op.f('ix_case_evidence_evidence_type'), table_name='case_evidence')
    op.drop_index(op.f('ix_case_evidence_alert_id'), table_name='case_evidence')
    op.drop_index(op.f('ix_case_evidence_case_id'), table_name='case_evidence')
    op.drop_table('case_evidence')

    # 2. Drop indexes and columns from cases
    op.drop_index(op.f('ix_cases_disposition'), table_name='cases')
    op.drop_index(op.f('ix_cases_assignee_id'), table_name='cases')
    op.drop_column('cases', 'resolved_by_id')
    op.drop_column('cases', 'resolved_at')
    op.drop_column('cases', 'resolution_summary')
    op.drop_column('cases', 'root_cause')
    op.drop_column('cases', 'disposition')
    op.drop_column('cases', 'assignee_id')

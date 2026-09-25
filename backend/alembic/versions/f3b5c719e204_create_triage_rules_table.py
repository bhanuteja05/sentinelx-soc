"""create triage rules table and seed baseline rules

Revision ID: f3b5c719e204
Revises: e1f34341c56e
Create Date: 2026-09-25 18:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'f3b5c719e204'
down_revision: Union[str, Sequence[str], None] = 'e1f34341c56e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: create triage_rules table and insert conservative baseline rules."""
    triage_rules_table = op.create_table(
        'triage_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('min_rule_level', sa.Integer(), nullable=True),
        sa.Column('rule_ids', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('mitre_techniques', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('mitre_tactics', postgresql.JSONB(astext_type=sa.Text()), server_default='[]', nullable=False),
        sa.Column('action_type', sa.String(length=32), server_default='correlate_or_create', nullable=False),
        sa.Column('case_severity', sa.String(length=32), server_default='high', nullable=False),
        sa.Column(
            'case_title_template',
            sa.String(length=255),
            server_default='[Auto-Triage] {rule_name}: {alert_description}',
            nullable=False,
        ),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_triage_rules_name'), 'triage_rules', ['name'], unique=True)
    op.create_index(op.f('ix_triage_rules_is_active'), 'triage_rules', ['is_active'], unique=False)

    # Seed approved conservative baseline rules
    op.bulk_insert(
        triage_rules_table,
        [
            {
                'name': 'Critical Alert Auto-Escalation',
                'description': 'Automatically escalates critical severity Wazuh alerts (rule level 12+) into an incident case or correlates into an active investigation.',
                'is_active': True,
                'min_rule_level': 12,
                'rule_ids': [],
                'mitre_techniques': [],
                'mitre_tactics': [],
                'action_type': 'correlate_or_create',
                'case_severity': 'critical',
                'case_title_template': '[Auto-Triage] Critical Severity Alert on {agent}',
            },
            {
                'name': 'Credential Access Threat Detection',
                'description': 'Detects MITRE Credential Access tactics and escalates to a high-severity investigation.',
                'is_active': True,
                'min_rule_level': None,
                'rule_ids': [],
                'mitre_techniques': [],
                'mitre_tactics': ['credential-access'],
                'action_type': 'correlate_or_create',
                'case_severity': 'high',
                'case_title_template': '[Auto-Triage] Credential Access Detected on {agent}',
            },
        ],
    )


def downgrade() -> None:
    """Downgrade schema: drop triage_rules table and indexes."""
    op.drop_index(op.f('ix_triage_rules_is_active'), table_name='triage_rules')
    op.drop_index(op.f('ix_triage_rules_name'), table_name='triage_rules')
    op.drop_table('triage_rules')

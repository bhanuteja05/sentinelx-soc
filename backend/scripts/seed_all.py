"""
backend/scripts/seed_all.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unified bootstrap script for seeding initial SOC operator accounts
and default baseline triage rules.
"""

import os
import sys

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.seed_users import seed_users
from scripts.seed_triage_rules import seed_triage_rules


def seed_all() -> int:
    print("=== Seeding Initial SOC Users ===")
    user_status = seed_users()
    if user_status != 0:
        print("WARNING: User seeding returned non-zero status.")

    print("\n=== Seeding Baseline Triage Rules ===")
    rule_status = seed_triage_rules()
    if rule_status != 0:
        print("WARNING: Triage rule seeding returned non-zero status.")

    return 0 if (user_status == 0 and rule_status == 0) else 1


if __name__ == "__main__":
    sys.exit(seed_all())

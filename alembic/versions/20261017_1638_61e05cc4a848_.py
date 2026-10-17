"""empty message

Revision ID: 61e05cc4a848
Revises: 743c0029929b
Create Date: 2026-10-17 16:38:27.912537

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '61e05cc4a848'
down_revision: Union[str, None] = '743c0029929b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("officers", sa.Column(
        "is_super_admin", sa.Boolean(), server_default=sa.text("false"), nullable=False))

    op.create_table(
        "counters",
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("next_value", sa.Integer(),
                  server_default=sa.text("1"), nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_counters")),
    )

    op.alter_column("officers", "role",
                    existing_type=sa.String(16), type_=sa.String(32),
                    existing_nullable=False)

    # Drop old constraints first (the data fix below would violate nothing, but
    # the old facility CHECK is being replaced anyway).
    op.drop_constraint(op.f("ck_officers_facility_required_unless_global"),
                       "officers", type_="check")
    op.drop_constraint(op.f("ck_officers_role_valid"),
                       "officers", type_="check")

    # Existing global accounts (the seed admin) become CSO-role.
    op.execute("UPDATE officers SET role = 'cso' "
               "WHERE facility_id IS NULL AND role <> 'cso'")

    op.create_check_constraint(
        op.f("ck_officers_role_valid"), "officers",
        "role IN ('officer', 'facility_manager', 'cso')")
    op.create_check_constraint(
        op.f("ck_officers_facility_required_unless_global"), "officers",
        "role IN ('cso') OR facility_id IS NOT NULL")
    op.create_check_constraint(
        op.f("ck_officers_super_admin_requires_admin"), "officers",
        "NOT is_super_admin OR is_admin")


def downgrade() -> None:
    op.drop_constraint(op.f("ck_officers_super_admin_requires_admin"),
                       "officers", type_="check")
    op.drop_constraint(op.f("ck_officers_facility_required_unless_global"),
                       "officers", type_="check")
    op.drop_constraint(op.f("ck_officers_role_valid"),
                       "officers", type_="check")

    op.execute("UPDATE officers SET role = 'officer' "
               "WHERE role = 'facility_manager'")

    op.create_check_constraint(
        op.f("ck_officers_role_valid"), "officers",
        "role IN ('officer', 'cso')")
    op.create_check_constraint(
        op.f("ck_officers_facility_required_unless_global"), "officers",
        "role = 'cso' OR is_admin OR facility_id IS NOT NULL")

    op.alter_column("officers", "role",
                    existing_type=sa.String(32), type_=sa.String(16),
                    existing_nullable=False)
    op.drop_table("counters")
    op.drop_column("officers", "is_super_admin")

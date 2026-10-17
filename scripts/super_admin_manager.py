

# scripts/super_admin_manager.py

"""The ONLY place super admins are created, promoted, demoted or PIN-reset.

    python -m scripts.super_admin_manager create --code SA-01 --name "Terry Fregene"
    python -m scripts.super_admin_manager promote --code CSO-001
    python -m scripts.super_admin_manager demote  --code SA-01
    python -m scripts.super_admin_manager reset-pin --code SA-01
    python -m scripts.super_admin_manager list

Add --facility CODE for accounts that belong to a facility. PINs are prompted
(hidden), never passed as arguments. A demoted super admin stays an ordinary
admin: remove admin powers or disable them afterwards from the super admin page.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.src.api.account_ops import revoke_all_sessions
from backend.src.db.orm.tables import Facility, Officer
from backend.src.db.session import create_session
from backend.src.models import Role
from backend.src.security.accounts import create_officer, find_officer
from backend.src.security.passwords import hash_pin, validate_pin_policy


def _prompt_pin() -> str | None:
    pin = getpass.getpass("PIN (6-10 digits): ")
    if pin != getpass.getpass("Repeat PIN: "):
        print("PINs do not match.", file=sys.stderr)
        return None
    return pin


def _active_super_admins(db: Session) -> int:
    return db.scalar(
        select(func.count()).select_from(Officer).where(
            Officer.is_super_admin.is_(True), Officer.is_active.is_(True))
    ) or 0


def cmd_create(db: Session, args: argparse.Namespace) -> int:
    pin = _prompt_pin()
    if pin is None:
        return 1
    officer = create_officer(
        db,
        officer_code=args.code,
        full_name=args.name,
        pin=pin,
        role=Role(args.role),
        is_admin=True,
        is_super_admin=True,
        facility_code=args.facility,
    )
    db.commit()
    print(f"Super admin {officer.officer_code} created (role={officer.role.value}). "
          f"id={officer.id}")
    return 0


def cmd_promote(db: Session, args: argparse.Namespace) -> int:
    officer = find_officer(db, officer_code=args.code,
                           facility_code=args.facility)
    if not officer.is_active:
        raise ValueError("That account is disabled. Enable it first.")
    officer.is_admin = True
    officer.is_super_admin = True
    db.commit()
    print(f"{officer.officer_code} is now a super admin.")
    return 0


def cmd_demote(db: Session, args: argparse.Namespace) -> int:
    officer = find_officer(db, officer_code=args.code,
                           facility_code=args.facility)
    if not officer.is_super_admin:
        raise ValueError("That account is not a super admin.")
    if officer.is_active and _active_super_admins(db) <= 1 and not args.force:
        raise ValueError(
            "This is the LAST active super admin. Create/promote another first, "
            "or pass --force if you really mean it.")
    officer.is_super_admin = False  # stays is_admin = True
    db.commit()
    print(f"{officer.officer_code} is now a plain admin (still is_admin).")
    return 0


def cmd_reset_pin(db: Session, args: argparse.Namespace) -> int:
    officer = find_officer(db, officer_code=args.code,
                           facility_code=args.facility)
    if not officer.is_super_admin:
        raise ValueError("CLI PIN reset is for super admins only.")
    pin = _prompt_pin()
    if pin is None:
        return 1
    validate_pin_policy(pin)
    officer.pin_hash = hash_pin(pin)
    officer.must_change_pin = False
    officer.failed_pin_attempts = 0
    officer.locked_until = None
    revoke_all_sessions(db, officer.id)
    db.commit()
    print(f"PIN reset for {officer.officer_code}; all sessions revoked.")
    return 0


def cmd_list(db: Session, _args: argparse.Namespace) -> int:
    rows = db.execute(
        select(Officer, Facility.code)
        .outerjoin(Facility, Facility.id == Officer.facility_id)
        .where(Officer.is_super_admin.is_(True))
        .order_by(Officer.officer_code)
    ).all()
    if not rows:
        print("No super admins.")
    for officer, fcode in rows:
        state = "active" if officer.is_active else "DISABLED"
        print(f"{officer.officer_code:<10} {officer.full_name:<28} "
              f"role={officer.role.value:<16} facility={fcode or '-':<12} {state}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage Tetracore Log super admins.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_target(p: argparse.ArgumentParser) -> None:
        p.add_argument("--code", required=True, help="officer code")
        p.add_argument("--facility", default=None,
                       help="facility code, if any")

    p = sub.add_parser("create", help="create a NEW super admin account")
    add_target(p)
    p.add_argument("--name", required=True)
    p.add_argument("--role", default=Role.CSO.value,
                   choices=[r.value for r in Role])
    p.set_defaults(fn=cmd_create)

    p = sub.add_parser(
        "promote", help="make an existing account a super admin")
    add_target(p)
    p.set_defaults(fn=cmd_promote)

    p = sub.add_parser("demote", help="super admin -> plain admin")
    add_target(p)
    p.add_argument("--force", action="store_true",
                   help="allow demoting the last active super admin")
    p.set_defaults(fn=cmd_demote)

    p = sub.add_parser("reset-pin", help="set a new PIN for a super admin")
    add_target(p)
    p.set_defaults(fn=cmd_reset_pin)

    p = sub.add_parser("list", help="list super admins")
    p.set_defaults(fn=cmd_list)

    args = parser.parse_args()
    with create_session() as db:
        try:
            return args.fn(db, args)
        except ValueError as exc:
            db.rollback()
            print(f"Error: {exc}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    raise SystemExit(main())


# scripts/admin_manager.py

"""Create an admin account. This is the ONLY way is_admin ever becomes true.

    python -m scripts.create_admin --code ADMIN-01 --name "Terry Fregene"
    python -m scripts.create_admin --code ADMIN-01 --name "Terry Fregene" --facility CNG-BEN-01

Without --facility the admin is a global account (facility_id NULL) and logs in
with no facility code. With --facility the admin also belongs to that station,
which lets you test entry endpoints with the same account.
The PIN is prompted for (hidden), never taken from the command line.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from backend.src.db.session import create_session
from backend.src.models import Role
from backend.src.security.accounts import create_officer


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a Tetracore Log admin.")
    parser.add_argument("--code", required=True,
                        help="officer code, e.g. ADMIN-01")
    parser.add_argument("--name", required=True, help="full name")
    parser.add_argument("--facility", default=None,
                        help="optional facility code")
    args = parser.parse_args()

    pin = getpass.getpass("PIN (6-10 digits): ")
    if pin != getpass.getpass("Repeat PIN: "):
        print("PINs do not match.", file=sys.stderr)
        return 1

    with create_session() as db:
        try:
            officer = create_officer(
                db,
                officer_code=args.code,
                full_name=args.name,
                pin=pin,
                role=Role.OFFICER,
                is_admin=True,
                facility_code=args.facility,
            )
            db.commit()
        except ValueError as exc:
            db.rollback()
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        scope = args.facility.upper() if args.facility else "global (no facility)"
        print(
            f"Admin {officer.officer_code} created. Scope: {scope}. id={officer.id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

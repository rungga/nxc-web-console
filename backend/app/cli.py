"""Administrative command-line utilities for NetExec Web GUI."""
from __future__ import annotations

import argparse
import getpass
import sys

from pydantic import ValidationError

from app import config, security
from app.schemas import UserPasswordResetRequest


def _reset_password(args: argparse.Namespace) -> int:
    username = args.username.strip()
    account = security.get_user(username)
    users = security.list_users()
    if not account and users:
        print(f"Account '{username}' does not exist.", file=sys.stderr)
        return 2
    if not account and username.casefold() != config.ADMIN_USERNAME.strip().casefold():
        print(f"The first account must be '{config.ADMIN_USERNAME}'.", file=sys.stderr)
        return 2

    password = getpass.getpass("New password: ")
    confirmation = getpass.getpass("Confirm new password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    try:
        validated = UserPasswordResetRequest(new_password=password)
    except ValidationError as exc:
        message = exc.errors()[0].get("msg", "Password does not meet policy")
        print(message, file=sys.stderr)
        return 2

    security.change_password(
        username,
        validated.new_password,
        must_change_password=not args.no_force_change,
    )
    suffix = " The user must change it after login." if not args.no_force_change else ""
    print(f"Password reset for '{username}'.{suffix}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nxc-web-console", description="NetExec Web Console administration")
    subparsers = parser.add_subparsers(dest="command", required=True)
    reset_parser = subparsers.add_parser("reset-password", help="reset an account password interactively")
    reset_parser.add_argument("--username", default=config.ADMIN_USERNAME)
    reset_parser.add_argument(
        "--no-force-change",
        action="store_true",
        help="do not require another password change after login",
    )
    reset_parser.set_defaults(handler=_reset_password)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
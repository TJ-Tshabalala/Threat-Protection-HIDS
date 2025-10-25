#!/usr/bin/env python3
"""CLI to rotate MASTER_KEY: decrypt using OLD_MASTER and re-encrypt using NEW_MASTER.

Usage:
  OLD_MASTER="old" NEW_MASTER="new" python server/rotate_master_cli.py
or
  python server/rotate_master_cli.py --old old --new new

This tool should be run in a secure environment where both values are provided
securely and not logged.
"""
import argparse
import os
from server import db


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--old", required=False, help="Old master key (or set OLD_MASTER env)")
    p.add_argument("--new", required=False, help="New master key (or set NEW_MASTER env)")
    args = p.parse_args()
    old = args.old or os.getenv("OLD_MASTER")
    new = args.new or os.getenv("NEW_MASTER")
    if not old or not new:
        print("Provide --old and --new or set OLD_MASTER and NEW_MASTER in the environment")
        raise SystemExit(2)
    count = db.reencrypt_master(old, new)
    print(f"Re-encrypted {count} agent records")


if __name__ == "__main__":
    main()

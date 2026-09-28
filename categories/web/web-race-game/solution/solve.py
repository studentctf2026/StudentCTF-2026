#!/usr/bin/env python3

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

try:
    import websocket
except ImportError as exc:  # pragma: no cover - friendly CLI error
    raise SystemExit("Missing dependency: install it with 'python3 -m pip install -r requirements.txt'") from exc


BASE_URL = os.environ.get("TARGET_URL", f"http://127.0.0.1:{os.environ.get('PORT', '3000')}").rstrip("/")
WS_URL = BASE_URL.replace("http://", "ws://", 1).replace("https://", "wss://", 1) + "/ws"
TIMEOUT = 5.0


def request(path, cookie=None):
    headers = {"Cookie": cookie} if cookie else {}
    request_obj = urllib.request.Request(BASE_URL + path, headers=headers)
    try:
        with urllib.request.urlopen(request_obj, timeout=TIMEOUT) as response:
            body = json.loads(response.read().decode("utf-8"))
            return body, response.headers
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP GET {path} failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach {BASE_URL}: {exc.reason}") from exc


def open_socket(cookie):
    try:
        socket = websocket.create_connection(WS_URL, cookie=cookie, timeout=TIMEOUT)
        initial = receive(socket)
        if initial.get("type") != "state":
            socket.close()
            raise RuntimeError(f"Unexpected initial WebSocket message: {initial}")
        return socket
    except Exception as exc:
        raise RuntimeError(f"WebSocket connection failed: {exc}") from exc


def receive(socket):
    try:
        return json.loads(socket.recv())
    except websocket.WebSocketTimeoutException as exc:
        raise RuntimeError("Timed out waiting for WebSocket message") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("Server sent invalid JSON") from exc


def wait_for(socket, predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    socket.settimeout(timeout)
    while time.monotonic() < deadline:
        message = receive(socket)
        if predicate(message):
            return message
    raise RuntimeError("Timed out waiting for expected WebSocket message")


def move(socket, direction, sequence, expected):
    socket.send(json.dumps({"type": "move", "direction": direction, "seq": sequence}))
    # A race broadcast may have left an older state frame queued on this socket.
    result = wait_for(
        socket,
        lambda message: message.get("type") == "error"
        or (message.get("type") == "state" and message.get("player", {}).get("lastSeq") == sequence),
    )
    if result.get("type") == "error":
        raise RuntimeError(f"Move {direction} #{sequence} rejected: {result.get('message')}")
    player = result.get("player", {})
    actual = (player.get("x"), player.get("y"), player.get("lastSeq"))
    wanted = (expected[0], expected[1], sequence)
    if actual != wanted:
        raise RuntimeError(f"Unexpected state after move #{sequence}: {actual}, expected {wanted}")
    time.sleep(0.12)


def collect(socket, package_id):
    socket.send(json.dumps({"type": "collect", "packageId": package_id}))
    result = wait_for(socket, lambda message: message.get("type") in ("state", "error"))
    if result.get("type") == "error":
        raise RuntimeError(f"Collect {package_id} rejected: {result.get('message')}")
    if package_id != "golden-package" and not any(
        item.get("id") == package_id and item.get("collected") for item in result.get("packages", [])
    ):
        raise RuntimeError(f"Server did not mark {package_id} as collected")


def wait_for_player(cookie, predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body, _ = request("/api/session", cookie)
        if predicate(body):
            return body
        time.sleep(0.035)
    raise RuntimeError("Timed out waiting for expected player state")


def main():
    health, _ = request("/healthz")
    if health.get("status") != "ok":
        raise RuntimeError(f"Healthcheck failed: {health}")

    _, headers = request("/api/session")
    set_cookie = headers.get("Set-Cookie")
    if not set_cookie:
        raise RuntimeError("Server did not set cc_session cookie")
    cookie = set_cookie.split(";", 1)[0]

    primary = open_socket(cookie)
    extra = []
    try:
        sequence = 1
        move(primary, "up", sequence, (1, 1)); sequence += 1
        collect(primary, "package-1")
        move(primary, "right", sequence, (2, 1)); sequence += 1
        move(primary, "right", sequence, (3, 1)); sequence += 1
        collect(primary, "package-2")
        move(primary, "down", sequence, (3, 2)); sequence += 1
        move(primary, "down", sequence, (3, 3)); sequence += 1
        collect(primary, "package-3")
        move(primary, "up", sequence, (3, 2)); sequence += 1

        first = open_socket(cookie)
        second = open_socket(cookie)
        extra.extend((first, second))
        race_sequence = sequence
        barrier = threading.Barrier(2)
        errors = []

        def send_race(socket):
            try:
                barrier.wait(timeout=2)
                socket.send(json.dumps({"type": "move", "direction": "right", "seq": race_sequence}))
            except Exception as exc:  # propagate worker failures to the main thread
                errors.append(exc)

        workers = [threading.Thread(target=send_race, args=(first,)), threading.Thread(target=send_race, args=(second,))]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=3)
        if errors:
            raise RuntimeError(f"Race send failed: {errors[0]}")
        wait_for_player(cookie, lambda body: body["player"]["x"] == 5 and body["player"]["lastSeq"] == race_sequence)
        # The second racing move updates lastMoveAt; respect the normal 100 ms cooldown.
        time.sleep(0.12)

        sequence += 1
        move(primary, "right", sequence, (6, 2))
        sequence += 1
        move(primary, "right", sequence, (7, 2))
        primary.send(json.dumps({"type": "collect", "packageId": "golden-package"}))
        flag_message = wait_for(primary, lambda message: message.get("type") in ("flag", "error"))
        if flag_message.get("type") != "flag":
            raise RuntimeError(f"Golden package rejected: {flag_message.get('message')}")
        print(flag_message["flag"])
    finally:
        primary.close()
        for socket in extra:
            socket.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Solve failed: {exc}", file=sys.stderr)
        sys.exit(1)

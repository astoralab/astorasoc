import json
import os
import sys
import urllib.error
import urllib.request


BASE_URL = os.environ.get("ASTORASOC_BASE_URL", "http://127.0.0.1:5001").rstrip("/")


def request(path, method="GET", body=None, headers=None, timeout=10):
    data = None
    request_headers = headers or {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers=request_headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def check(name, ok, detail):
    status = "OK" if ok else "FAIL"
    print(f"[{status}] {name}: {detail}")
    return ok


def load_env_value(key):
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if not os.path.exists(env_path):
        return os.environ.get(key)
    with open(env_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name == key:
                return value
    return os.environ.get(key)


def main():
    results = []

    status, body = request("/healthz")
    results.append(check("health", status == 200 and '"status":"ok"' in body.replace(" ", ""), f"HTTP {status}"))

    status, _ = request("/login")
    results.append(check("login page", status == 200, f"HTTP {status}"))

    status, _ = request("/dashboard")
    results.append(check("protected dashboard", status in {200, 302}, f"HTTP {status}"))

    if os.environ.get("ASTORASOC_SMOKE_WEBHOOK") == "1":
        api_key = load_env_value("WEBHOOK_API_KEY")
        payload = {
            "source": "SmokeTest",
            "event_id": "smoke-check-do-not-use",
            "title": "AstoraSOC smoke test alert",
            "severity": "low",
            "host": "smoke-test-host",
            "raw_alert": {"smoke": True},
        }
        status, _ = request("/api/webhook/alert", method="POST", body=payload, headers={"X-API-Key": api_key or ""})
        results.append(check("webhook", status in {200, 201, 409}, f"HTTP {status}"))
    else:
        print("[SKIP] webhook: set ASTORASOC_SMOKE_WEBHOOK=1 to send a test alert")

    if not all(results):
        sys.exit(1)


if __name__ == "__main__":
    main()

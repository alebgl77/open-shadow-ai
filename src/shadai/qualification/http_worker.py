"""Standalone stdlib HTTP worker; only a bounded private stdin envelope is accepted."""

import base64
import json
import math
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_BODY = 16 * 1048576
MAX_INPUT = 4 * ((MAX_BODY + 2) // 3) + 65536
MAX_RESPONSE = 65536


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def exchange(envelope):
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema",
        "method",
        "url",
        "body",
        "credential",
        "timeout_seconds",
    }:
        raise ValueError
    parsed = urlsplit(envelope["url"])
    timeout = envelope["timeout_seconds"]
    credential = envelope["credential"]
    if (
        type(envelope["schema"]) is not int
        or envelope["schema"] != 1
        or envelope["method"] not in {"GET", "POST"}
        or not isinstance(envelope["url"], str)
        or len(envelope["url"]) > 8192
        or any(ord(char) < 32 for char in envelope["url"])
        or parsed.scheme not in {"https", "http"}
        or parsed.scheme == "http"
        and parsed.hostname != "127.0.0.1"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or type(timeout) not in {int, float}
        or not math.isfinite(timeout)
        or not 0 < timeout <= 86400
        or not isinstance(credential, str)
        or len(credential) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in credential)
    ):
        raise ValueError
    body = base64.b64decode(envelope["body"], validate=True)
    if len(body) > MAX_BODY or envelope["method"] == "GET" and (body or credential):
        raise ValueError
    headers = {"Accept": "application/json"}
    if envelope["method"] == "POST":
        headers.update({"Content-Type": "application/json", "X-API-Key": credential})
    request = Request(
        envelope["url"],
        data=body if envelope["method"] == "POST" else None,
        headers=headers,
        method=envelope["method"],
    )
    try:
        # No environment proxy, redirect or insecure TLS fallback can change the target.
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=timeout) as reply:
            content = reply.read(MAX_RESPONSE + 1)
            if len(content) > MAX_RESPONSE:
                return {"schema": 1, "status": reply.status, "body": "", "error": "body_limit"}
            return {"schema": 1, "status": reply.status, "body": base64.b64encode(content).decode(), "error": "none"}
    except HTTPError as error:
        status = error.code
        error.close()
        return {"schema": 1, "status": status, "body": "", "error": "none"}
    except Exception:
        return {"schema": 1, "status": 0, "body": "", "error": "transport"}


def main():
    result = {"schema": 1, "status": 0, "body": "", "error": "protocol"}
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) <= MAX_INPUT:
            result = exchange(json.loads(raw))
    except Exception:
        pass
    sys.stdout.write(json.dumps(result, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()

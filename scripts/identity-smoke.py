"""Live optional Compose acceptance: provider metadata and SCIM via the frontend proxy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID

PREFIX = "/api/v1/scim/v2"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
USER_EXTERNAL_ID = "ci-scim-user-00000001"
GROUP_EXTERNAL_ID = "ci-scim-analysts"  # Must match the CI SCIM_GROUP_ROLE_MAP.
MAX_RESPONSE_BYTES = 65536


class SmokeError(Exception):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeError(message)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.opener = build_opener(NoRedirect())

    def request(self, method, path, expected=200, payload=None, headers=None):
        context = f"{method} {path.split('?')[0]}"
        headers = {"Authorization": "Bearer " + self.token} if headers is None else dict(headers)
        headers["Accept"] = "application/scim+json, application/json"
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/scim+json"
            data = json.dumps(payload).encode()
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            try:
                response = self.opener.open(request, timeout=10)
            except HTTPError as error:
                response = error
            with response:
                check(response.status == expected, f"{context}: expected HTTP {expected}, got {response.status}")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                check(len(raw) <= MAX_RESPONSE_BYTES, f"{context}: response exceeds limit")
                if expected == 204:
                    check(not raw, f"{context}: expected an empty response")
                    return None
                media_type = "application/scim+json" if path.startswith(PREFIX) else "application/json"
                check(response.headers.get_content_type() == media_type, f"{context}: unexpected content type")
        except (OSError, URLError):
            raise SmokeError(f"{context}: request failed") from None
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise SmokeError(f"{context}: invalid JSON response") from None
        check(isinstance(result, dict), f"{context}: expected a JSON object")
        if expected >= 400:
            check(result.get("schemas") == [ERROR_SCHEMA], f"{context}: missing SCIM error schema")
            check(result.get("status") == str(expected), f"{context}: invalid SCIM error status")
            check(isinstance(result.get("detail"), str), f"{context}: missing SCIM error detail")
        return result


def resource_id(result, schema):
    check(result.get("schemas") == [schema], "Unexpected SCIM resource schema")
    try:
        return str(UUID(result["id"]))
    except (KeyError, ValueError, TypeError, AttributeError):
        raise SmokeError("Invalid SCIM resource ID") from None


def patch(operation):
    return {"schemas": [PATCH_SCHEMA], "Operations": [operation]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:3000")
    args = parser.parse_args()
    fixtures = Path(__file__).resolve().parents[1] / "secrets"
    try:
        token = (fixtures / "scim_bearer_token.txt").read_text().strip()
        agent_key = (fixtures / "agent_api_key.txt").read_text().strip()
    except OSError:
        raise SmokeError("Could not read identity smoke fixture files") from None
    check(bool(token) and bool(agent_key) and token != agent_key, "Invalid identity smoke fixture credentials")
    client = Client(args.base_url, token)
    providers = client.request("GET", "/api/v1/auth/providers", headers={})
    check(providers.get("local_enabled") is True, "Local login is not enabled")
    check(providers.get("sso", {}).get("enabled") is True, "SSO provider is not enabled")
    check(providers["sso"].get("label") == "CI identity provider", "Unexpected SSO provider label")

    users, groups = PREFIX + "/Users", PREFIX + "/Groups"
    for headers in (
        {},
        {"Authorization": "Bearer ci-deliberately-invalid-provisioning-token"},
        {"Authorization": "Bearer " + agent_key},
        {"X-API-Key": agent_key},
    ):
        client.request("GET", users, 401, headers=headers)
    query = urlencode({"filter": 'userName eq "ci-scim-missing@example.test"', "count": 1})
    listing = client.request("GET", users + "?" + query)
    check(listing.get("schemas") == [LIST_SCHEMA], "Missing SCIM list schema")
    check(listing.get("totalResults") == 0 and listing.get("Resources") == [], "Expected an empty SCIM list")
    check(listing.get("startIndex") == 1 and listing.get("itemsPerPage") == 0, "Invalid SCIM list pagination")

    user_payload = {
        "schemas": [USER_SCHEMA],
        "externalId": USER_EXTERNAL_ID,
        "userName": "ci-scim-user@example.test",
        "name": {"givenName": "CI", "familyName": "Smoke"},
        "active": True,
    }
    user = client.request("POST", users, 201, user_payload)
    user_id = resource_id(user, USER_SCHEMA)
    user_url = users + "/" + user_id
    for field in ("externalId", "userName", "name", "active"):
        check(user.get(field) == user_payload[field], f"Created SCIM user has unexpected {field}")
    group = client.request("POST", groups, 201, {
        "schemas": [GROUP_SCHEMA],
        "externalId": GROUP_EXTERNAL_ID,
        "displayName": "CI smoke analysts",
        "members": [{"value": user_id}],
    })
    group_id = resource_id(group, GROUP_SCHEMA)
    group_url = groups + "/" + group_id
    check(group.get("externalId") == GROUP_EXTERNAL_ID, "Unexpected SCIM group external ID")
    user = client.request("GET", user_url)
    group = client.request("GET", group_url)
    check([item["value"] for item in user.get("groups", [])] == [group_id], "User group membership was not stored")
    check([item["value"] for item in group.get("members", [])] == [user_id], "Group membership was not stored")

    client.request("PATCH", group_url, 204, patch({
        "op": "remove", "path": "members", "value": [{"value": user_id}],
    }))
    check(client.request("GET", group_url).get("members") == [], "Group member removal was not stored")
    check(client.request("GET", user_url).get("groups") == [], "User group removal was not stored")
    for active in (False, True):
        client.request("PATCH", user_url, 200, patch({"op": "replace", "path": "active", "value": active}))
        check(client.request("GET", user_url).get("active") is active, "User activation change was not stored")
    client.request("DELETE", user_url, 204)
    client.request("GET", user_url, 404)
    client.request("DELETE", group_url, 204)
    client.request("GET", group_url, 404)
    print("PASS: optional identity startup, frontend proxy, provider metadata, SCIM authentication and lifecycle")


if __name__ == "__main__":
    try:
        main()
    except SmokeError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
    except (KeyError, TypeError, AttributeError):
        print("FAIL: unexpected identity response structure", file=sys.stderr)
        sys.exit(1)

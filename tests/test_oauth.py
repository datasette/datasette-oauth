from datasette.app import Datasette
import pytest
import json
import secrets
import hashlib
from urllib.parse import urlencode, urlparse, parse_qs


@pytest.fixture
def datasette():
    return Datasette(memory=True)


def actor_cookie(ds, actor):
    return ds.sign({"a": actor}, "actor")


def auth_cookies(ds, actor_id="test-user"):
    return {"ds_actor": actor_cookie(ds, {"id": actor_id})}


async def csrf_post(ds, path, data, cookies=None, follow_redirects=False):
    """POST with proper CSRF handling."""
    cookies = dict(cookies or {})
    # First GET to obtain a CSRF token
    get_response = await ds.client.get(path, cookies=cookies)
    if "ds_csrftoken" in get_response.cookies:
        csrf_token = get_response.cookies["ds_csrftoken"]
    else:
        # Try a simple GET to any page
        get_response = await ds.client.get("/", cookies=cookies)
        csrf_token = get_response.cookies.get("ds_csrftoken", "")
    cookies["ds_csrftoken"] = csrf_token
    data["csrftoken"] = csrf_token
    return await ds.client.post(
        path,
        content=urlencode(data),
        headers={"content-type": "application/x-www-form-urlencoded"},
        cookies=cookies,
        follow_redirects=follow_redirects,
    )


@pytest.mark.asyncio
async def test_plugin_is_installed():
    datasette = Datasette(memory=True)
    response = await datasette.client.get("/-/plugins.json")
    assert response.status_code == 200
    installed_plugins = {p["name"] for p in response.json()}
    assert "datasette-oauth" in installed_plugins


# --- Phase 1: Startup & Schema ---


@pytest.mark.asyncio
async def test_startup_creates_tables(datasette):
    # Trigger startup by making any request
    await datasette.client.get("/")
    internal = datasette.get_internal_database()
    # Check oauth_clients table exists
    result = await internal.execute(
        "select name from sqlite_master where type='table' and name='oauth_clients'"
    )
    assert result.rows, "oauth_clients table should exist"
    # Check oauth_authorization_codes table exists
    result = await internal.execute(
        "select name from sqlite_master where type='table' and name='oauth_authorization_codes'"
    )
    assert result.rows, "oauth_authorization_codes table should exist"


# --- Phase 2: Client Registration ---


@pytest.mark.asyncio
async def test_register_client_requires_auth(datasette):
    response = await csrf_post(datasette, "/-/oauth/clients.json", {})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_register_client(datasette):
    cookies = auth_cookies(datasette)
    response = await csrf_post(
        datasette,
        "/-/oauth/clients.json",
        {
            "client_name": "My Test App",
            "redirect_uri": "https://example.com/callback",
        },
        cookies=cookies,
    )
    assert response.status_code == 200
    data = response.json()
    assert "client_id" in data
    assert "client_secret" in data
    assert data["client_name"] == "My Test App"
    assert data["redirect_uri"] == "https://example.com/callback"
    # client_id and client_secret should be non-empty strings
    assert len(data["client_id"]) > 0
    assert len(data["client_secret"]) > 0


@pytest.mark.asyncio
async def test_register_client_missing_fields(datasette):
    cookies = auth_cookies(datasette)
    response = await csrf_post(
        datasette,
        "/-/oauth/clients.json",
        {"client_name": "My Test App"},
        cookies=cookies,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_list_clients(datasette):
    cookies = auth_cookies(datasette)
    # Register a client first
    await csrf_post(
        datasette,
        "/-/oauth/clients.json",
        {
            "client_name": "My Test App",
            "redirect_uri": "https://example.com/callback",
        },
        cookies=cookies,
    )
    # List clients
    response = await datasette.client.get("/-/oauth/clients.json", cookies=cookies)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["client_name"] == "My Test App"
    # Secret should NOT be in the list response
    assert "client_secret" not in data[0]
    assert "client_secret_hash" not in data[0]


@pytest.mark.asyncio
async def test_list_clients_requires_auth(datasette):
    response = await datasette.client.get("/-/oauth/clients.json")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_clients_html_page(datasette):
    cookies = auth_cookies(datasette)
    response = await datasette.client.get("/-/oauth/clients", cookies=cookies)
    assert response.status_code == 200
    html = response.text
    assert "<h1>OAuth Clients</h1>" in html
    assert 'id="clients-list"' in html
    assert 'name="client_name"' in html
    assert 'name="redirect_uri"' in html
    assert "/-/oauth/clients.json" in html


@pytest.mark.asyncio
async def test_clients_html_page_requires_auth(datasette):
    response = await datasette.client.get("/-/oauth/clients")
    assert response.status_code == 403


# --- Phase 3: Authorization Endpoint GET (consent screen) ---


async def register_client(datasette, actor_id="test-user"):
    """Helper: register a client and return client_id, client_secret."""
    cookies = auth_cookies(datasette, actor_id)
    response = await csrf_post(
        datasette,
        "/-/oauth/clients.json",
        {
            "client_name": "My Test App",
            "redirect_uri": "https://example.com/callback",
        },
        cookies=cookies,
    )
    data = response.json()
    return data["client_id"], data["client_secret"]


@pytest.mark.asyncio
async def test_authorize_get_shows_consent(datasette):
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"], ["view-table", "mydb", "users"]])
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode(
            {
                "client_id": client_id,
                "redirect_uri": "https://example.com/callback",
                "scope": scope,
                "state": "random-state",
                "response_type": "code",
            }
        ),
        cookies=cookies,
    )
    assert response.status_code == 200
    html = response.text
    assert "My Test App" in html
    assert "view-instance" in html
    assert "view-table" in html


@pytest.mark.asyncio
async def test_authorize_get_requires_auth(datasette):
    client_id, _ = await register_client(datasette)
    scope = json.dumps([["view-instance"]])
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode(
            {
                "client_id": client_id,
                "redirect_uri": "https://example.com/callback",
                "scope": scope,
                "state": "random-state",
                "response_type": "code",
            }
        ),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_authorize_get_invalid_client(datasette):
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode(
            {
                "client_id": "nonexistent",
                "redirect_uri": "https://example.com/callback",
                "scope": scope,
                "state": "random-state",
                "response_type": "code",
            }
        ),
        cookies=cookies,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_authorize_get_redirect_uri_mismatch(datasette):
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode(
            {
                "client_id": client_id,
                "redirect_uri": "https://evil.com/callback",
                "scope": scope,
                "state": "random-state",
                "response_type": "code",
            }
        ),
        cookies=cookies,
    )
    assert response.status_code == 400


# --- Phase 4: Authorization Endpoint POST (process consent) ---


@pytest.mark.asyncio
async def test_authorize_post_approve(datasette):
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"], ["view-table", "mydb", "users"]])
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "random-state",
            "response_type": "code",
            "scope_0": "on",
            "scope_1": "on",
        },
        cookies=cookies,
    )
    # Should redirect back to the app with a code
    assert response.status_code == 302
    location = response.headers["location"]
    parsed = urlparse(location)
    assert parsed.scheme == "https"
    assert parsed.netloc == "example.com"
    assert parsed.path == "/callback"
    qs = parse_qs(parsed.query)
    assert "code" in qs
    assert qs["state"] == ["random-state"]


@pytest.mark.asyncio
async def test_authorize_post_deny(datasette):
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "random-state",
            "response_type": "code",
            "deny": "1",
        },
        cookies=cookies,
    )
    assert response.status_code == 302
    location = response.headers["location"]
    qs = parse_qs(urlparse(location).query)
    assert qs["error"] == ["access_denied"]
    assert qs["state"] == ["random-state"]


async def authorize_and_get_code(datasette, client_id, scope, cookies):
    """Helper: authorize and extract the code from redirect."""
    scope_data = {
        "client_id": client_id,
        "redirect_uri": "https://example.com/callback",
        "scope": scope,
        "state": "s",
        "response_type": "code",
    }
    scopes = json.loads(scope)
    for i in range(len(scopes)):
        scope_data[f"scope_{i}"] = "on"
    response = await csrf_post(
        datasette, "/-/oauth/authorize", scope_data, cookies=cookies
    )
    assert response.status_code == 302
    return parse_qs(urlparse(response.headers["location"]).query)["code"][0]


@pytest.mark.asyncio
async def test_authorize_post_partial_scopes(datasette):
    """User unchecks one of two scopes."""
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"], ["view-table", "mydb", "users"]])
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "random-state",
            "response_type": "code",
            # Only approve scope_0, NOT scope_1
            "scope_0": "on",
        },
        cookies=cookies,
    )
    assert response.status_code == 302
    location = response.headers["location"]
    qs = parse_qs(urlparse(location).query)
    assert "code" in qs

    # Now exchange the code and verify the token only has view-instance
    code = qs["code"][0]
    token_response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": "https://example.com/callback",
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert token_response.status_code == 200
    token_data = token_response.json()
    access_token = token_data["access_token"]

    # Use the token - should work for view-instance
    assert access_token.startswith("dstok_")

    # Verify the token's restrictions by decoding it
    decoded = datasette.unsign(access_token[len("dstok_") :], "token")
    assert "_r" in decoded
    # Should only have view-instance in global restrictions
    assert "a" in decoded["_r"]
    # Should NOT have resource-level restrictions for mydb:users
    assert "r" not in decoded["_r"]


# --- Phase 5: Token Exchange ---


@pytest.mark.asyncio
async def test_token_exchange(datasette):
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    code = await authorize_and_get_code(datasette, client_id, scope, cookies)

    # Exchange code for token (no CSRF needed - skip_csrf for this endpoint)
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": "https://example.com/callback",
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["access_token"].startswith("dstok_")


@pytest.mark.asyncio
async def test_token_exchange_wrong_secret(datasette):
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    code = await authorize_and_get_code(datasette, client_id, scope, cookies)

    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": "wrong-secret",
                "redirect_uri": "https://example.com/callback",
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_token_exchange_code_reuse(datasette):
    """Authorization codes should be single-use."""
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    code = await authorize_and_get_code(datasette, client_id, scope, cookies)

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": "https://example.com/callback",
    }

    # First exchange should succeed
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(token_data),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200

    # Second exchange should fail
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(token_data),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_token_exchange_redirect_uri_mismatch(datasette):
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    code = await authorize_and_get_code(datasette, client_id, scope, cookies)

    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": "https://evil.com/callback",
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400


# --- Phase 6: End-to-end ---


@pytest.mark.asyncio
async def test_full_oauth_flow_with_restricted_token(datasette):
    """End-to-end: register client, authorize, exchange, use token."""
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)

    scope = json.dumps(
        [
            ["view-instance"],
            ["view-database", "mydb"],
            ["view-table", "mydb", "users"],
        ]
    )

    # Step 1: User visits authorize endpoint
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode(
            {
                "client_id": client_id,
                "redirect_uri": "https://example.com/callback",
                "scope": scope,
                "state": "xyz",
                "response_type": "code",
            }
        ),
        cookies=cookies,
    )
    assert response.status_code == 200

    # Step 2: User approves all scopes
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "xyz",
            "response_type": "code",
            "scope_0": "on",
            "scope_1": "on",
            "scope_2": "on",
        },
        cookies=cookies,
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    # Step 3: App exchanges code for token
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": "https://example.com/callback",
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    token_data = response.json()
    access_token = token_data["access_token"]

    # Step 4: Verify the token encodes the right restrictions
    decoded = datasette.unsign(access_token[len("dstok_") :], "token")
    assert decoded["a"] == "test-user"
    assert "_r" in decoded


@pytest.mark.asyncio
async def test_authorize_post_requires_auth(datasette):
    client_id, _ = await register_client(datasette)
    scope = json.dumps([["view-instance"]])
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "s",
            "response_type": "code",
            "scope_0": "on",
        },
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_scope_parsing():
    """Test that scope JSON arrays are parsed correctly into token restrictions."""
    from datasette_oauth import parse_scopes

    scopes = [
        ["view-instance"],
        ["view-database", "mydb"],
        ["view-table", "mydb", "users"],
        ["insert-row", "mydb", "logs"],
    ]
    restrict_all, restrict_database, restrict_resource = parse_scopes(scopes)
    assert restrict_all == ["view-instance"]
    assert restrict_database == {"mydb": ["view-database"]}
    assert restrict_resource == {
        "mydb": {
            "users": ["view-table"],
            "logs": ["insert-row"],
        }
    }


# --- Device Authorization Flow ---


@pytest.mark.asyncio
async def test_device_flow_initiate(datasette):
    """POST /-/oauth/device returns device_code, user_code, verification_uri."""
    response = await datasette.client.post(
        "/-/oauth/device",
        content=urlencode({"scope": "[]"}),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "device_code" in data
    assert "user_code" in data
    assert "verification_uri" in data
    assert "expires_in" in data
    assert "interval" in data
    # user_code should be in XXXX-XXXX format
    assert len(data["user_code"]) == 9
    assert data["user_code"][4] == "-"


@pytest.mark.asyncio
async def test_device_flow_verify_requires_auth(datasette):
    """GET /-/oauth/device/verify requires authentication."""
    response = await datasette.client.get("/-/oauth/device/verify")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_device_flow_verify_invalid_code(datasette):
    """POST with an invalid code shows error."""
    cookies = auth_cookies(datasette)
    response = await csrf_post(
        datasette,
        "/-/oauth/device/verify",
        {"code": "ZZZZ-ZZZZ"},
        cookies=cookies,
    )
    assert response.status_code == 200
    assert "Invalid code" in response.text


@pytest.mark.asyncio
async def test_device_flow_full(datasette):
    """Full device flow: initiate, verify, exchange for token."""
    # Step 1: Initiate device flow
    response = await datasette.client.post(
        "/-/oauth/device",
        content=urlencode({"scope": json.dumps([["view-instance"]])}),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    device_data = response.json()
    device_code = device_data["device_code"]
    user_code = device_data["user_code"]

    # Step 2: Poll should return authorization_pending
    poll_response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert poll_response.status_code == 400
    assert poll_response.json()["error"] == "authorization_pending"

    # Step 3: User approves
    cookies = auth_cookies(datasette)
    approve_response = await csrf_post(
        datasette,
        "/-/oauth/device/verify",
        {"code": user_code},
        cookies=cookies,
    )
    assert approve_response.status_code == 200
    assert "authorized successfully" in approve_response.text

    # Step 4: Poll again — should get token
    token_response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert token_response.status_code == 200
    token_data = token_response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert token_data["access_token"].startswith("dstok_")

    # Verify token encodes the right restrictions
    decoded = datasette.unsign(token_data["access_token"][len("dstok_") :], "token")
    assert decoded["a"] == "test-user"
    assert "_r" in decoded


@pytest.mark.asyncio
async def test_device_flow_deny(datasette):
    """User denies device authorization."""
    # Initiate
    response = await datasette.client.post(
        "/-/oauth/device",
        content=urlencode({"scope": "[]"}),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    device_data = response.json()
    device_code = device_data["device_code"]
    user_code = device_data["user_code"]

    # User denies
    cookies = auth_cookies(datasette)
    deny_response = await csrf_post(
        datasette,
        "/-/oauth/device/verify",
        {"code": user_code, "deny": "1"},
        cookies=cookies,
    )
    assert deny_response.status_code == 200
    assert "denied" in deny_response.text

    # Poll should return access_denied
    poll_response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert poll_response.status_code == 400
    assert poll_response.json()["error"] == "access_denied"


@pytest.mark.asyncio
async def test_device_flow_code_reuse(datasette):
    """Device codes should be single-use."""
    # Initiate and approve
    response = await datasette.client.post(
        "/-/oauth/device",
        content=urlencode({"scope": "[]"}),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    device_data = response.json()
    device_code = device_data["device_code"]
    user_code = device_data["user_code"]

    cookies = auth_cookies(datasette)
    await csrf_post(
        datasette,
        "/-/oauth/device/verify",
        {"code": user_code},
        cookies=cookies,
    )

    # First exchange succeeds
    token_response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert token_response.status_code == 200

    # Second exchange fails
    token_response2 = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert token_response2.status_code == 400
    assert token_response2.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_device_flow_no_scopes_gives_unrestricted_token(datasette):
    """Device flow with empty scopes gives an unrestricted token."""
    # Initiate with no scopes
    response = await datasette.client.post(
        "/-/oauth/device",
        content=urlencode({"scope": "[]"}),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    device_data = response.json()
    device_code = device_data["device_code"]
    user_code = device_data["user_code"]

    # Approve
    cookies = auth_cookies(datasette)
    await csrf_post(
        datasette,
        "/-/oauth/device/verify",
        {"code": user_code},
        cookies=cookies,
    )

    # Exchange
    token_response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            }
        ),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert token_response.status_code == 200
    token_data = token_response.json()

    # Token should be unrestricted (no _r key)
    decoded = datasette.unsign(token_data["access_token"][len("dstok_") :], "token")
    assert decoded["a"] == "test-user"
    assert "_r" not in decoded

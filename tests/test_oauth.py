from datasette.app import Datasette
import pytest
import json
import secrets
import hashlib
import base64
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
    response = await csrf_post(datasette, "/-/oauth/clients", {})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_register_client(datasette):
    cookies = auth_cookies(datasette)
    response = await csrf_post(
        datasette,
        "/-/oauth/clients",
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
        "/-/oauth/clients",
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
        "/-/oauth/clients",
        {
            "client_name": "My Test App",
            "redirect_uri": "https://example.com/callback",
        },
        cookies=cookies,
    )
    # List clients
    response = await datasette.client.get("/-/oauth/clients", cookies=cookies)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["client_name"] == "My Test App"
    # Secret should NOT be in the list response
    assert "client_secret" not in data[0]
    assert "client_secret_hash" not in data[0]


@pytest.mark.asyncio
async def test_list_clients_requires_auth(datasette):
    response = await datasette.client.get("/-/oauth/clients")
    assert response.status_code == 403


# --- Phase 3: Authorization Endpoint GET (consent screen) ---


async def register_client(datasette, actor_id="test-user"):
    """Helper: register a client and return client_id, client_secret."""
    cookies = auth_cookies(datasette, actor_id)
    response = await csrf_post(
        datasette,
        "/-/oauth/clients",
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
        + urlencode({
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "random-state",
            "response_type": "code",
        }),
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
        + urlencode({
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "random-state",
            "response_type": "code",
        }),
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_authorize_get_invalid_client(datasette):
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode({
            "client_id": "nonexistent",
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "random-state",
            "response_type": "code",
        }),
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
        + urlencode({
            "client_id": client_id,
            "redirect_uri": "https://evil.com/callback",
            "scope": scope,
            "state": "random-state",
            "response_type": "code",
        }),
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
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "https://example.com/callback",
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert token_response.status_code == 200
    token_data = token_response.json()
    access_token = token_data["access_token"]

    # Use the token - should work for view-instance
    assert access_token.startswith("dstok_")

    # Verify the token's restrictions by decoding it
    decoded = datasette.unsign(access_token[len("dstok_"):], "token")
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
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "https://example.com/callback",
        }),
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
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": "wrong-secret",
            "redirect_uri": "https://example.com/callback",
        }),
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
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "https://evil.com/callback",
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400


# --- Phase 6: End-to-end ---


@pytest.mark.asyncio
async def test_full_oauth_flow_with_restricted_token(datasette):
    """End-to-end: register client, authorize, exchange, use token."""
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)

    scope = json.dumps([
        ["view-instance"],
        ["view-database", "mydb"],
        ["view-table", "mydb", "users"],
    ])

    # Step 1: User visits authorize endpoint
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode({
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "xyz",
            "response_type": "code",
        }),
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
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "https://example.com/callback",
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    token_data = response.json()
    access_token = token_data["access_token"]

    # Step 4: Verify the token encodes the right restrictions
    decoded = datasette.unsign(access_token[len("dstok_"):], "token")
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


# --- Phase 7: PKCE (Proof Key for Code Exchange, RFC 7636) ---


def generate_pkce_pair():
    """Generate a code_verifier and its S256 code_challenge."""
    code_verifier = secrets.token_urlsafe(32)  # 43 chars
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


@pytest.mark.asyncio
async def test_pkce_authorize_stores_challenge(datasette):
    """Authorize GET should accept code_challenge and code_challenge_method params."""
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    _, code_challenge = generate_pkce_pair()
    scope = json.dumps([["view-instance"]])
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode({
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "pkce-state",
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }),
        cookies=cookies,
    )
    assert response.status_code == 200
    # The consent screen should render normally with PKCE params
    assert "My Test App" in response.text


@pytest.mark.asyncio
async def test_pkce_full_flow(datasette):
    """Full PKCE flow: authorize with challenge, exchange with verifier."""
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)
    code_verifier, code_challenge = generate_pkce_pair()
    scope = json.dumps([["view-instance"]])

    # Authorize with code_challenge
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "pkce-state",
            "response_type": "code",
            "scope_0": "on",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies=cookies,
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    # Exchange with code_verifier (and client_secret for confidential client)
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "https://example.com/callback",
            "code_verifier": code_verifier,
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"].startswith("dstok_")
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_pkce_exchange_without_client_secret(datasette):
    """PKCE allows token exchange without client_secret (public client)."""
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    code_verifier, code_challenge = generate_pkce_pair()
    scope = json.dumps([["view-instance"]])

    # Authorize with code_challenge
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "pkce-state",
            "response_type": "code",
            "scope_0": "on",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies=cookies,
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    # Exchange with code_verifier but NO client_secret
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "code_verifier": code_verifier,
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"].startswith("dstok_")


@pytest.mark.asyncio
async def test_pkce_wrong_verifier(datasette):
    """Token exchange should fail if code_verifier doesn't match code_challenge."""
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)
    _, code_challenge = generate_pkce_pair()
    scope = json.dumps([["view-instance"]])

    # Authorize with code_challenge
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "pkce-state",
            "response_type": "code",
            "scope_0": "on",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies=cookies,
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    # Exchange with WRONG code_verifier
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "https://example.com/callback",
            "code_verifier": "totally-wrong-verifier-value-here",
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_pkce_missing_verifier_when_challenge_was_set(datasette):
    """If code_challenge was provided at auth time, code_verifier is required at token time."""
    client_id, client_secret = await register_client(datasette)
    cookies = auth_cookies(datasette)
    _, code_challenge = generate_pkce_pair()
    scope = json.dumps([["view-instance"]])

    # Authorize with code_challenge
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "pkce-state",
            "response_type": "code",
            "scope_0": "on",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies=cookies,
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    # Exchange WITHOUT code_verifier — should fail
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": "https://example.com/callback",
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_pkce_no_client_secret_no_challenge_rejected(datasette):
    """Without PKCE and without client_secret, token exchange must fail."""
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])

    # Authorize without code_challenge
    code = await authorize_and_get_code(datasette, client_id, scope, cookies)

    # Exchange with neither client_secret nor code_verifier
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


@pytest.mark.asyncio
async def test_pkce_unsupported_challenge_method(datasette):
    """Only S256 challenge method is supported."""
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode({
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "pkce-state",
            "response_type": "code",
            "code_challenge": "some-challenge",
            "code_challenge_method": "plain",
        }),
        cookies=cookies,
    )
    assert response.status_code == 400
    assert "S256" in response.json().get("error", "")


@pytest.mark.asyncio
async def test_pkce_challenge_without_method_defaults_to_error(datasette):
    """code_challenge without code_challenge_method should be rejected."""
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    scope = json.dumps([["view-instance"]])
    response = await datasette.client.get(
        "/-/oauth/authorize?"
        + urlencode({
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "pkce-state",
            "response_type": "code",
            "code_challenge": "some-challenge",
        }),
        cookies=cookies,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_pkce_end_to_end_with_partial_scopes(datasette):
    """PKCE flow with user unchecking some scopes, no client_secret."""
    client_id, _ = await register_client(datasette)
    cookies = auth_cookies(datasette)
    code_verifier, code_challenge = generate_pkce_pair()
    scope = json.dumps([["view-instance"], ["view-table", "mydb", "users"]])

    # Authorize with PKCE, only approve scope_0
    response = await csrf_post(
        datasette,
        "/-/oauth/authorize",
        {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": scope,
            "state": "pkce-state",
            "response_type": "code",
            "scope_0": "on",
            # scope_1 is NOT approved
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        cookies=cookies,
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

    # Exchange with code_verifier only (public client)
    response = await datasette.client.post(
        "/-/oauth/token",
        content=urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "code_verifier": code_verifier,
        }),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    access_token = response.json()["access_token"]

    # Verify only view-instance is in the token
    decoded = datasette.unsign(access_token[len("dstok_"):], "token")
    assert "_r" in decoded
    assert "a" in decoded["_r"]
    # Should NOT have resource-level restrictions
    assert "r" not in decoded["_r"]

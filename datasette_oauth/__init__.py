from datasette import hookimpl
from datasette.permissions import Action, PermissionSQL
from datasette.tokens import TokenRestrictions
from datasette.utils.asgi import Response
import json
import secrets
import hashlib
import string
import time
from urllib.parse import urlencode

DEVICE_TOKEN_TTL_OPTIONS = [
    (900, "15 minutes"),
    (3600, "1 hour"),
    (28800, "8 hours"),
    (86400, "24 hours"),
    (604800, "7 days"),
    (2592000, "30 days"),
]
DEFAULT_DEVICE_TOKEN_TTL_SECONDS = 3600
ALLOWED_DEVICE_TOKEN_TTL_SECONDS = {seconds for seconds, _ in DEVICE_TOKEN_TTL_OPTIONS}


def build_restrictions(scopes):
    """Parse a list of scope arrays into a TokenRestrictions object.

    Each scope is a JSON array:
      ["action"]                    -> allow_all
      ["action", "database"]        -> allow_database
      ["action", "database", "resource"] -> allow_resource

    Returns a TokenRestrictions instance, or None if no scopes.
    """
    if not scopes:
        return None

    restrictions = TokenRestrictions()
    for scope in scopes:
        if len(scope) == 1:
            restrictions = restrictions.allow_all(scope[0])
        elif len(scope) == 2:
            action, database = scope
            restrictions = restrictions.allow_database(database, action)
        elif len(scope) == 3:
            action, database, resource = scope
            restrictions = restrictions.allow_resource(database, resource, action)

    return restrictions


def _hash_secret(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def _parse_scope_list(scope_raw):
    scopes = json.loads(scope_raw)
    if not isinstance(scopes, list):
        raise ValueError("scope must be a JSON array")
    for scope in scopes:
        if not isinstance(scope, list):
            raise ValueError("each scope must be an array")
        if not 1 <= len(scope) <= 3:
            raise ValueError("scope arrays must have 1-3 elements")
        if not all(isinstance(part, str) for part in scope):
            raise ValueError("scope elements must be strings")
    return scopes


def _device_scope_summary(scope_raw):
    try:
        scopes = _parse_scope_list(scope_raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {
            "scopes": [],
            "scope_raw": scope_raw,
            "full_access": False,
            "scope_error": "Invalid scope data for this request",
        }
    return {
        "scopes": [{"label": _scope_label(scope)} for scope in scopes],
        "scope_raw": scope_raw,
        "full_access": not scopes,
        "scope_error": None,
    }


def _device_ttl_options(selected=None):
    if selected is None:
        selected = str(DEFAULT_DEVICE_TOKEN_TTL_SECONDS)
    else:
        selected = str(selected)
    return [
        {"value": str(seconds), "label": label, "selected": str(seconds) == selected}
        for seconds, label in DEVICE_TOKEN_TTL_OPTIONS
    ]


def _parse_device_token_ttl(value):
    if value in (None, ""):
        return DEFAULT_DEVICE_TOKEN_TTL_SECONDS
    try:
        ttl = int(value)
    except (TypeError, ValueError):
        return None
    if ttl not in ALLOWED_DEVICE_TOKEN_TTL_SECONDS:
        return None
    return ttl


async def _render_device_verify(
    datasette,
    request,
    *,
    user_code="",
    error=None,
    success=False,
    review_request=False,
    scope_raw="[]",
    selected_ttl_seconds=None,
):
    context = {
        "user_code": user_code,
        "error": error,
        "success": success,
        "review_request": review_request,
        "ttl_options": _device_ttl_options(selected_ttl_seconds),
        "default_ttl_seconds": str(DEFAULT_DEVICE_TOKEN_TTL_SECONDS),
    }
    if review_request:
        context.update(_device_scope_summary(scope_raw))
    html = await datasette.render_template(
        "oauth_device_verify.html",
        context,
        request=request,
    )
    return Response.html(html)


async def _get_device_code_by_user_code(datasette, user_code):
    internal = datasette.get_internal_database()
    result = await internal.execute(
        "SELECT device_code, user_code, scope, expires_at, status, actor_id, token_ttl_seconds "
        "FROM oauth_device_codes WHERE user_code = ?",
        [user_code],
    )
    rows = result.rows
    if not rows:
        return None
    return dict(rows[0])


@hookimpl
def startup(datasette):
    async def inner():
        internal = datasette.get_internal_database()
        await internal.execute_write_script("""
            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_secret_hash TEXT NOT NULL,
                client_name TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES oauth_clients(client_id),
                actor_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS oauth_device_codes (
                device_code TEXT PRIMARY KEY,
                user_code TEXT NOT NULL UNIQUE,
                scope TEXT NOT NULL DEFAULT '[]',
                expires_at TEXT NOT NULL,
                interval INTEGER NOT NULL DEFAULT 5,
                status TEXT NOT NULL DEFAULT 'pending',
                actor_id TEXT,
                token_ttl_seconds INTEGER
            );
            """)
        table_info = await internal.execute("PRAGMA table_info(oauth_device_codes)")
        column_names = {row["name"] for row in table_info.rows}
        if "token_ttl_seconds" not in column_names:
            await internal.execute_write(
                "ALTER TABLE oauth_device_codes ADD COLUMN token_ttl_seconds INTEGER"
            )

    return inner


def _require_auth(request):
    if not request.actor or not request.actor.get("id"):
        return Response.json({"error": "Authentication required"}, status=403)
    if request.actor.get("token"):
        return Response.json(
            {"error": "Token authentication cannot be used here"}, status=403
        )
    return None


async def _require_manage_clients(request, datasette):
    auth_error = _require_auth(request)
    if auth_error:
        return auth_error
    if not await datasette.allowed(actor=request.actor, action="oauth-manage-clients"):
        return Response.json({"error": "Permission denied"}, status=403)
    return None


async def _get_client(datasette, client_id):
    internal = datasette.get_internal_database()
    result = await internal.execute(
        "SELECT client_id, client_secret_hash, client_name, redirect_uri, created_by, created_at "
        "FROM oauth_clients WHERE client_id = ?",
        [client_id],
    )
    rows = result.rows
    if not rows:
        return None
    row = dict(rows[0])
    return row


async def oauth_clients_html(request, datasette):
    auth_error = await _require_manage_clients(request, datasette)
    if auth_error:
        return auth_error
    html = await datasette.render_template(
        "oauth_clients.html",
        request=request,
    )
    return Response.html(html)


async def oauth_clients_json(request, datasette):
    if request.method == "GET":
        return await _oauth_clients_list(request, datasette)
    elif request.method == "POST":
        return await _oauth_clients_register(request, datasette)
    return Response.json({"error": "Method not allowed"}, status=405)


async def _oauth_clients_list(request, datasette):
    auth_error = await _require_manage_clients(request, datasette)
    if auth_error:
        return auth_error

    internal = datasette.get_internal_database()
    result = await internal.execute(
        "SELECT client_id, client_name, redirect_uri, created_by, created_at "
        "FROM oauth_clients WHERE created_by = ?",
        [request.actor["id"]],
    )
    clients = [dict(row) for row in result.rows]
    return Response.json(clients)


async def _oauth_clients_register(request, datasette):
    auth_error = await _require_manage_clients(request, datasette)
    if auth_error:
        return auth_error

    post_vars = await request.post_vars()
    client_name = post_vars.get("client_name", "").strip()
    redirect_uri = post_vars.get("redirect_uri", "").strip()

    if not client_name or not redirect_uri:
        return Response.json(
            {"error": "client_name and redirect_uri are required"}, status=400
        )

    client_id = secrets.token_hex(16)
    client_secret = secrets.token_hex(32)

    internal = datasette.get_internal_database()
    await internal.execute_write(
        "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uri, created_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            client_id,
            _hash_secret(client_secret),
            client_name,
            redirect_uri,
            request.actor["id"],
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ],
    )

    return Response.json(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "redirect_uri": redirect_uri,
        }
    )


async def oauth_client_detail_json(request, datasette):
    client_id = request.url_vars["client_id"]
    if request.method == "POST":
        return await _oauth_client_edit(request, datasette, client_id)
    elif request.method == "DELETE":
        return await _oauth_client_delete(request, datasette, client_id)
    return Response.json({"error": "Method not allowed"}, status=405)


async def _oauth_client_edit(request, datasette, client_id):
    auth_error = await _require_manage_clients(request, datasette)
    if auth_error:
        return auth_error

    client = await _get_client(datasette, client_id)
    if not client:
        return Response.json({"error": "Client not found"}, status=404)
    if client["created_by"] != request.actor["id"]:
        return Response.json({"error": "Forbidden"}, status=403)

    post_vars = await request.post_vars()
    client_name = post_vars.get("client_name", "").strip()
    redirect_uri = post_vars.get("redirect_uri", "").strip()

    if not client_name or not redirect_uri:
        return Response.json(
            {"error": "client_name and redirect_uri are required"}, status=400
        )

    internal = datasette.get_internal_database()
    await internal.execute_write(
        "UPDATE oauth_clients SET client_name = ?, redirect_uri = ? WHERE client_id = ?",
        [client_name, redirect_uri, client_id],
    )

    return Response.json(
        {
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uri": redirect_uri,
        }
    )


async def _oauth_client_delete(request, datasette, client_id):
    auth_error = await _require_manage_clients(request, datasette)
    if auth_error:
        return auth_error

    client = await _get_client(datasette, client_id)
    if not client:
        return Response.json({"error": "Client not found"}, status=404)
    if client["created_by"] != request.actor["id"]:
        return Response.json({"error": "Forbidden"}, status=403)

    internal = datasette.get_internal_database()
    await internal.execute_write(
        "DELETE FROM oauth_clients WHERE client_id = ?",
        [client_id],
    )

    return Response.json({"ok": True})


def _scope_label(scope):
    """Human-readable label for a scope array."""
    if len(scope) == 1:
        return scope[0]
    elif len(scope) == 2:
        return f"{scope[0]} on database {scope[1]}"
    elif len(scope) == 3:
        return f"{scope[0]} on {scope[1]}/{scope[2]}"
    return json.dumps(scope)


def _device_code_error_message(device_row):
    if device_row["status"] != "pending":
        return "This code has already been used"
    if time.time() > float(device_row["expires_at"]):
        return "This code has expired"
    return None


async def oauth_authorize(request, datasette):
    if request.method == "GET":
        return await _oauth_authorize_get(request, datasette)
    elif request.method == "POST":
        return await _oauth_authorize_post(request, datasette)
    return Response.json({"error": "Method not allowed"}, status=405)


async def _oauth_authorize_get(request, datasette):
    auth_error = _require_auth(request)
    if auth_error:
        return auth_error

    client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    scope_raw = request.args.get("scope", "")
    state = request.args.get("state", "")
    response_type = request.args.get("response_type", "")

    # Validate client
    client = await _get_client(datasette, client_id)
    if not client:
        return Response.json({"error": "Invalid client_id"}, status=400)

    if client["redirect_uri"] != redirect_uri:
        return Response.json({"error": "redirect_uri mismatch"}, status=400)

    # Parse scopes
    try:
        scopes = json.loads(scope_raw)
    except (json.JSONDecodeError, TypeError):
        return Response.json({"error": "Invalid scope"}, status=400)

    scope_items = [{"label": _scope_label(scope)} for scope in scopes]

    html = await datasette.render_template(
        "oauth_authorize.html",
        {
            "client_name": client["client_name"],
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope_raw": scope_raw,
            "state": state,
            "response_type": response_type,
            "scopes": scope_items,
        },
        request=request,
    )
    return Response.html(html)


async def _oauth_authorize_post(request, datasette):
    auth_error = _require_auth(request)
    if auth_error:
        return auth_error

    post_vars = await request.post_vars()
    client_id = post_vars.get("client_id", "")
    redirect_uri = post_vars.get("redirect_uri", "")
    scope_raw = post_vars.get("scope", "")
    state = post_vars.get("state", "")
    deny = post_vars.get("deny", "")

    # Validate client
    client = await _get_client(datasette, client_id)
    if not client:
        return Response.json({"error": "Invalid client_id"}, status=400)

    if client["redirect_uri"] != redirect_uri:
        return Response.json({"error": "redirect_uri mismatch"}, status=400)

    # If user denied
    if deny:
        return Response.redirect(
            redirect_uri + "?" + urlencode({"error": "access_denied", "state": state})
        )

    # Parse original scopes and filter to only checked ones
    try:
        scopes = json.loads(scope_raw)
    except (json.JSONDecodeError, TypeError):
        return Response.json({"error": "Invalid scope"}, status=400)

    approved_scopes = []
    for i, scope in enumerate(scopes):
        if post_vars.get(f"scope_{i}"):
            approved_scopes.append(scope)

    if not approved_scopes:
        return Response.redirect(
            redirect_uri + "?" + urlencode({"error": "access_denied", "state": state})
        )

    # Generate authorization code
    code = secrets.token_hex(32)
    now = time.time()
    expires_at = now + 600  # 10 minutes

    internal = datasette.get_internal_database()
    await internal.execute_write(
        "INSERT INTO oauth_authorization_codes "
        "(code, client_id, actor_id, redirect_uri, scope, created_at, expires_at, used) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        [
            code,
            client_id,
            request.actor["id"],
            redirect_uri,
            json.dumps(approved_scopes),
            str(now),
            str(expires_at),
        ],
    )

    return Response.redirect(
        redirect_uri + "?" + urlencode({"code": code, "state": state})
    )


async def oauth_token(request, datasette):
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)

    post_vars = await request.post_vars()
    grant_type = post_vars.get("grant_type", "")

    if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        return await _oauth_token_device_code(post_vars, datasette)

    code = post_vars.get("code", "")
    client_id = post_vars.get("client_id", "")
    client_secret = post_vars.get("client_secret", "")
    redirect_uri = post_vars.get("redirect_uri", "")

    if grant_type != "authorization_code":
        return Response.json({"error": "unsupported_grant_type"}, status=400)

    # Validate client
    client = await _get_client(datasette, client_id)
    if not client:
        return Response.json({"error": "invalid_client"}, status=401)

    # Verify client secret
    if _hash_secret(client_secret) != client["client_secret_hash"]:
        return Response.json({"error": "invalid_client"}, status=401)

    # Look up authorization code
    internal = datasette.get_internal_database()
    result = await internal.execute(
        "SELECT code, client_id, actor_id, redirect_uri, scope, created_at, expires_at, used "
        "FROM oauth_authorization_codes WHERE code = ?",
        [code],
    )
    rows = result.rows
    if not rows:
        return Response.json({"error": "invalid_grant"}, status=400)

    auth_code = dict(rows[0])

    # Validate the code
    if auth_code["used"]:
        return Response.json({"error": "invalid_grant"}, status=400)

    if auth_code["client_id"] != client_id:
        return Response.json({"error": "invalid_grant"}, status=400)

    if auth_code["redirect_uri"] != redirect_uri:
        return Response.json({"error": "invalid_grant"}, status=400)

    if time.time() > float(auth_code["expires_at"]):
        return Response.json({"error": "invalid_grant"}, status=400)

    # Atomically consume the code so concurrent exchanges cannot both succeed
    consume_result = await internal.execute_write(
        "UPDATE oauth_authorization_codes SET used = 1 WHERE code = ? AND used = 0",
        [code],
    )
    if consume_result.rowcount != 1:
        return Response.json({"error": "invalid_grant"}, status=400)

    # Parse approved scopes and create a restricted token
    approved_scopes = json.loads(auth_code["scope"])
    restrictions = build_restrictions(approved_scopes)

    token = await datasette.create_token(
        auth_code["actor_id"],
        restrictions=restrictions,
    )

    return Response.json(
        {
            "access_token": token,
            "token_type": "bearer",
        }
    )


def _generate_user_code():
    """Generate a short, human-friendly user code like ABCD-EFGH."""
    chars = string.ascii_uppercase + string.digits
    # Remove confusing characters
    chars = (
        chars.replace("O", "")
        .replace("0", "")
        .replace("I", "")
        .replace("1", "")
        .replace("L", "")
    )
    part1 = "".join(secrets.choice(chars) for _ in range(4))
    part2 = "".join(secrets.choice(chars) for _ in range(4))
    return f"{part1}-{part2}"


async def oauth_device(request, datasette):
    """POST /-/oauth/device — initiate device authorization flow."""
    if request.method != "POST":
        return Response.json({"error": "Method not allowed"}, status=405)

    post_vars = await request.post_vars()
    scope_raw = post_vars.get("scope", "[]")

    # Validate scope JSON
    try:
        scopes = _parse_scope_list(scope_raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return Response.json({"error": "Invalid scope"}, status=400)

    device_code = secrets.token_hex(32)
    user_code = _generate_user_code()
    now = time.time()
    expires_at = now + 900  # 15 minutes
    interval = 5

    internal = datasette.get_internal_database()
    await internal.execute_write(
        "INSERT INTO oauth_device_codes "
        "(device_code, user_code, scope, expires_at, interval, status, actor_id, token_ttl_seconds) "
        "VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL)",
        [device_code, user_code, json.dumps(scopes), str(expires_at), interval],
    )

    base_url = datasette.absolute_url(request, "/-/oauth/device/verify")

    return Response.json(
        {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": base_url,
            "expires_in": 900,
            "interval": interval,
        }
    )


async def oauth_device_verify(request, datasette):
    """GET/POST /-/oauth/device/verify — user enters code and approves."""
    if request.method == "GET":
        return await _oauth_device_verify_get(request, datasette)
    elif request.method == "POST":
        return await _oauth_device_verify_post(request, datasette)
    return Response.json({"error": "Method not allowed"}, status=405)


async def _require_device_tokens(request, datasette):
    auth_error = _require_auth(request)
    if auth_error:
        return auth_error
    if not await datasette.allowed(
        actor=request.actor, action="oauth-device-tokens"
    ):
        return Response.json({"error": "Permission denied"}, status=403)
    return None


async def _oauth_device_verify_get(request, datasette):
    auth_error = await _require_device_tokens(request, datasette)
    if auth_error:
        return auth_error

    user_code = request.args.get("code", "")
    normalized_user_code = user_code.strip().upper()
    if not normalized_user_code:
        return await _render_device_verify(datasette, request, user_code=user_code)

    device_row = await _get_device_code_by_user_code(datasette, normalized_user_code)
    if not device_row:
        return await _render_device_verify(
            datasette, request, user_code=normalized_user_code, error="Invalid code"
        )

    error = _device_code_error_message(device_row)
    if error:
        return await _render_device_verify(
            datasette, request, user_code=normalized_user_code, error=error
        )

    return await _render_device_verify(
        datasette,
        request,
        user_code=normalized_user_code,
        review_request=True,
        scope_raw=device_row["scope"],
    )


async def _oauth_device_verify_post(request, datasette):
    auth_error = await _require_device_tokens(request, datasette)
    if auth_error:
        return auth_error

    post_vars = await request.post_vars()
    user_code = post_vars.get("code", "").strip().upper()
    deny = post_vars.get("deny", "")
    confirm = post_vars.get("confirm", "")

    device_row = await _get_device_code_by_user_code(datasette, user_code)
    if not device_row:
        return await _render_device_verify(
            datasette, request, user_code=user_code, error="Invalid code"
        )

    error = _device_code_error_message(device_row)
    if error:
        return await _render_device_verify(
            datasette, request, user_code=user_code, error=error
        )

    if not confirm:
        return await _render_device_verify(
            datasette,
            request,
            user_code=user_code,
            review_request=True,
            scope_raw=device_row["scope"],
        )

    if deny:
        internal = datasette.get_internal_database()
        await internal.execute_write(
            "UPDATE oauth_device_codes SET status = 'denied' WHERE user_code = ?",
            [user_code],
        )
        return await _render_device_verify(
            datasette,
            request,
            user_code=user_code,
            error="Authorization denied",
        )

    token_ttl_seconds = _parse_device_token_ttl(post_vars.get("token_ttl_seconds"))
    if token_ttl_seconds is None:
        return await _render_device_verify(
            datasette,
            request,
            user_code=user_code,
            error="Invalid token time limit",
            review_request=True,
            scope_raw=device_row["scope"],
            selected_ttl_seconds=post_vars.get("token_ttl_seconds"),
        )

    internal = datasette.get_internal_database()
    # Approve — set status to approved, record the actor, and persist chosen TTL
    await internal.execute_write(
        "UPDATE oauth_device_codes "
        "SET status = 'approved', actor_id = ?, token_ttl_seconds = ? "
        "WHERE user_code = ?",
        [request.actor["id"], token_ttl_seconds, user_code],
    )

    return await _render_device_verify(
        datasette,
        request,
        user_code=user_code,
        success=True,
    )


async def _oauth_token_device_code(post_vars, datasette):
    """Handle grant_type=urn:ietf:params:oauth:grant-type:device_code."""
    device_code = post_vars.get("device_code", "")

    internal = datasette.get_internal_database()
    result = await internal.execute(
        "SELECT device_code, user_code, scope, expires_at, status, actor_id, token_ttl_seconds "
        "FROM oauth_device_codes WHERE device_code = ?",
        [device_code],
    )
    rows = result.rows
    if not rows:
        return Response.json({"error": "invalid_grant"}, status=400)

    device_row = dict(rows[0])

    if time.time() > float(device_row["expires_at"]):
        return Response.json({"error": "expired_token"}, status=400)

    if device_row["status"] == "pending":
        return Response.json({"error": "authorization_pending"}, status=400)

    if device_row["status"] == "denied":
        return Response.json({"error": "access_denied"}, status=400)

    if device_row["status"] == "used":
        return Response.json({"error": "invalid_grant"}, status=400)

    # status == "approved" — issue a token
    approved_scopes = json.loads(device_row["scope"])

    restrictions = build_restrictions(approved_scopes)
    token_ttl_seconds = (
        device_row.get("token_ttl_seconds") or DEFAULT_DEVICE_TOKEN_TTL_SECONDS
    )
    # Atomically consume approved device codes before token creation so
    # concurrent polls cannot receive multiple tokens for one authorization.
    consume_result = await internal.execute_write(
        "UPDATE oauth_device_codes SET status = 'used' "
        "WHERE device_code = ? AND status = 'approved'",
        [device_code],
    )
    if consume_result.rowcount != 1:
        return Response.json({"error": "invalid_grant"}, status=400)

    token = await datasette.create_token(
        device_row["actor_id"],
        expires_after=int(token_ttl_seconds),
        restrictions=restrictions,
    )

    return Response.json(
        {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": int(token_ttl_seconds),
        }
    )


@hookimpl
def skip_csrf(datasette, scope):
    """Skip CSRF for machine-to-machine endpoints and DELETE on client detail."""
    if scope["type"] != "http":
        return
    token_path = datasette.urls.path("/-/oauth/token")
    device_path = datasette.urls.path("/-/oauth/device")
    clients_prefix = datasette.urls.path("/-/oauth/clients/")
    if scope["path"] in (token_path, device_path):
        return True
    if (
        scope.get("method") == "DELETE"
        and scope["path"].startswith(clients_prefix)
        and scope["path"].endswith(".json")
    ):
        return True


@hookimpl
def register_actions(datasette):
    return [
        Action(
            name="oauth-manage-clients",
            description="Manage OAuth clients (register, edit, delete)",
        ),
        Action(
            name="oauth-device-tokens",
            description="Authorize device token requests",
        ),
    ]


@hookimpl
def permission_resources_sql(datasette, actor, action):
    if action != "oauth-device-tokens":
        return None
    if actor is None or actor.get("id") != "root":
        return None
    config = datasette.plugin_config("datasette-oauth") or {}
    if config.get("allow_root_device_tokens"):
        return None
    return PermissionSQL.deny(reason="Root cannot use device tokens by default")


@hookimpl
def register_routes(datasette):
    return [
        (r"^/-/oauth/clients$", oauth_clients_html),
        (r"^/-/oauth/clients\.json$", oauth_clients_json),
        (r"^/-/oauth/clients/(?P<client_id>[^/]+)\.json$", oauth_client_detail_json),
        (r"^/-/oauth/authorize$", oauth_authorize),
        (r"^/-/oauth/token$", oauth_token),
        (r"^/-/oauth/device$", oauth_device),
        (r"^/-/oauth/device/verify$", oauth_device_verify),
    ]

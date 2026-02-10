from datasette import hookimpl
from datasette.utils.asgi import Response
import json
import secrets
import hashlib
import time
from urllib.parse import urlencode


def parse_scopes(scopes):
    """Parse a list of scope arrays into Datasette token restriction args.

    Each scope is a JSON array:
      ["action"]                    -> restrict_all
      ["action", "database"]        -> restrict_database
      ["action", "database", "resource"] -> restrict_resource

    Returns (restrict_all, restrict_database, restrict_resource).
    """
    restrict_all = []
    restrict_database = {}
    restrict_resource = {}

    for scope in scopes:
        if len(scope) == 1:
            restrict_all.append(scope[0])
        elif len(scope) == 2:
            action, database = scope
            restrict_database.setdefault(database, []).append(action)
        elif len(scope) == 3:
            action, database, resource = scope
            restrict_resource.setdefault(database, {}).setdefault(
                resource, []
            ).append(action)

    return restrict_all, restrict_database, restrict_resource


def _hash_secret(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


@hookimpl
def startup(datasette):
    async def inner():
        internal = datasette.get_internal_database()
        await internal.execute_write_script(
            """
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
            """
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


async def oauth_clients(request, datasette):
    if request.method == "GET":
        return await _oauth_clients_list(request, datasette)
    elif request.method == "POST":
        return await _oauth_clients_register(request, datasette)
    return Response.json({"error": "Method not allowed"}, status=405)


async def _oauth_clients_list(request, datasette):
    auth_error = _require_auth(request)
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
    auth_error = _require_auth(request)
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


def _scope_label(scope):
    """Human-readable label for a scope array."""
    if len(scope) == 1:
        return scope[0]
    elif len(scope) == 2:
        return f"{scope[0]} on database {scope[1]}"
    elif len(scope) == 3:
        return f"{scope[0]} on {scope[1]}/{scope[2]}"
    return json.dumps(scope)


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

    # Build consent screen HTML
    scope_checkboxes = []
    for i, scope in enumerate(scopes):
        label = _scope_label(scope)
        scope_checkboxes.append(
            f'<label><input type="checkbox" name="scope_{i}" checked> {label}</label>'
        )

    html = f"""<!DOCTYPE html>
<html>
<head><title>Authorize {client["client_name"]}</title></head>
<body>
<h1>Authorize {client["client_name"]}</h1>
<p><strong>{client["client_name"]}</strong> is requesting access to your Datasette account.</p>
<p>It will redirect you to: <code>{redirect_uri}</code></p>
<form method="post" action="/-/oauth/authorize">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="scope" value='{scope_raw}'>
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="response_type" value="{response_type}">
  <h2>Requested permissions:</h2>
  <ul>
    {"".join(f"<li>{cb}</li>" for cb in scope_checkboxes)}
  </ul>
  <button type="submit">Authorize</button>
  <button type="submit" name="deny" value="1">Deny</button>
</form>
</body>
</html>"""

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

    # Mark code as used
    await internal.execute_write(
        "UPDATE oauth_authorization_codes SET used = 1 WHERE code = ?",
        [code],
    )

    # Parse approved scopes and create a restricted token
    approved_scopes = json.loads(auth_code["scope"])
    restrict_all, restrict_database, restrict_resource = parse_scopes(approved_scopes)

    token = datasette.create_token(
        auth_code["actor_id"],
        restrict_all=restrict_all or None,
        restrict_database=restrict_database or None,
        restrict_resource=restrict_resource or None,
    )

    return Response.json(
        {
            "access_token": token,
            "token_type": "bearer",
        }
    )


@hookimpl
def skip_csrf(scope):
    """Skip CSRF for the token endpoint — it uses client_secret auth."""
    if scope["type"] == "http" and scope["path"] == "/-/oauth/token":
        return True


@hookimpl
def register_routes(datasette):
    return [
        (r"^/-/oauth/clients$", oauth_clients),
        (r"^/-/oauth/authorize$", oauth_authorize),
        (r"^/-/oauth/token$", oauth_token),
    ]

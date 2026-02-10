# datasette-oauth

[![PyPI](https://img.shields.io/pypi/v/datasette-oauth.svg)](https://pypi.org/project/datasette-oauth/)
[![Changelog](https://img.shields.io/github/v/release/datasette/datasette-oauth?include_prereleases&label=changelog)](https://github.com/datasette/datasette-oauth/releases)
[![Tests](https://github.com/datasette/datasette-oauth/actions/workflows/test.yml/badge.svg)](https://github.com/datasette/datasette-oauth/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/datasette/datasette-oauth/blob/main/LICENSE)

Datasette as an OAuth provider. Allows third-party applications to request access to a Datasette instance on behalf of signed-in users, using the OAuth 2.0 Authorization Code flow. Supports PKCE ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)) for public clients like JavaScript SPAs and CLI tools.

Access tokens are standard Datasette restricted API tokens (`dstok_...`), so all existing permission checks work automatically.

## Installation

Install this plugin in the same environment as Datasette.

```bash
datasette install datasette-oauth
```

## How it works

```
Third-party App                  Datasette                        User
      |                               |                             |
      |-- 1. Redirect user ---------->|                             |
      |   GET /-/oauth/authorize      |                             |
      |   ?client_id=...              |-- 2. Show consent screen -->|
      |   &redirect_uri=...           |                             |
      |   &scope=...                  |<-- 3. User approves --------|
      |   &state=...                  |                             |
      |   &response_type=code         |                             |
      |   [&code_challenge=... PKCE]  |                             |
      |                               |                             |
      |<-- 4. Redirect with code -----|                             |
      |   redirect_uri?code=...       |                             |
      |                               |                             |
      |-- 5. Exchange code ---------->|                             |
      |   POST /-/oauth/token         |                             |
      |   code=...                    |                             |
      |   &client_secret=...          |                             |
      |   (or &code_verifier=... PKCE)|                             |
      |                               |                             |
      |<-- 6. Access token -----------|                             |
      |   {"access_token":"dstok_..."}|                             |
```

## Endpoints

### Register a client: `POST /-/oauth/clients`

Requires authentication. Creates a new OAuth client application.

```bash
curl -X POST 'https://datasette.example.com/-/oauth/clients' \
  -H 'Cookie: ds_actor=...' \
  -d 'client_name=My App&redirect_uri=https://myapp.example.com/callback'
```

Response:

```json
{
  "client_id": "a1b2c3...",
  "client_secret": "d4e5f6...",
  "client_name": "My App",
  "redirect_uri": "https://myapp.example.com/callback"
}
```

The `client_secret` is shown **once** at registration time. It is stored as a SHA-256 hash.

### List your clients: `GET /-/oauth/clients`

Requires authentication. Returns clients registered by the current user.

```json
[
  {
    "client_id": "a1b2c3...",
    "client_name": "My App",
    "redirect_uri": "https://myapp.example.com/callback",
    "created_by": "user-id",
    "created_at": "2025-01-15T10:30:00Z"
  }
]
```

### Authorization: `GET /-/oauth/authorize`

Redirect the user here to request authorization. Parameters:

| Parameter | Required | Description |
|---|---|---|
| `client_id` | Yes | The registered client ID |
| `redirect_uri` | Yes | Must exactly match the registered redirect URI |
| `scope` | Yes | JSON array of scope arrays (see below) |
| `state` | Yes | Opaque value passed back to prevent CSRF |
| `response_type` | Yes | Must be `code` |

The user sees a consent screen showing the app name and requested permissions, each with a checkbox. They can uncheck permissions they don't want to grant.

### Process consent: `POST /-/oauth/authorize`

When the user clicks "Authorize", they are redirected back to the `redirect_uri` with:

```
https://myapp.example.com/callback?code=abc123...&state=your-state
```

If the user clicks "Deny":

```
https://myapp.example.com/callback?error=access_denied&state=your-state
```

### Exchange code for token: `POST /-/oauth/token`

For confidential clients (with `client_secret`):

```bash
curl -X POST 'https://datasette.example.com/-/oauth/token' \
  -d 'grant_type=authorization_code' \
  -d 'code=abc123...' \
  -d 'client_id=a1b2c3...' \
  -d 'client_secret=d4e5f6...' \
  -d 'redirect_uri=https://myapp.example.com/callback'
```

For public clients using PKCE (with `code_verifier`):

```bash
curl -X POST 'https://datasette.example.com/-/oauth/token' \
  -d 'grant_type=authorization_code' \
  -d 'code=abc123...' \
  -d 'client_id=a1b2c3...' \
  -d 'redirect_uri=https://myapp.example.com/callback' \
  -d 'code_verifier=your-original-code-verifier'
```

Response:

```json
{
  "access_token": "dstok_...",
  "token_type": "bearer"
}
```

Authorization codes expire after 10 minutes and are single-use.

## Scope format

Scopes are JSON arrays describing permissions at different levels:

| Scope | Meaning |
|---|---|
| `["view-instance"]` | Global permission |
| `["view-database", "mydb"]` | Permission on a specific database |
| `["view-table", "mydb", "users"]` | Permission on a specific table |

Multiple scopes are passed as a JSON array of arrays:

```json
[
  ["view-instance"],
  ["view-database", "mydb"],
  ["view-table", "mydb", "users"],
  ["insert-row", "mydb", "logs"]
]
```

This maps directly to Datasette's existing token restriction system (`restrict_all`, `restrict_database`, `restrict_resource`).

## PKCE (Proof Key for Code Exchange)

PKCE ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)) allows public clients — JavaScript SPAs, mobile apps, CLI tools — to use the OAuth flow without a `client_secret`. Instead, the client proves its identity with a one-time cryptographic challenge.

### How it works

1. Client generates a random `code_verifier` (43-128 URL-safe characters)
2. Client computes `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Client includes `code_challenge` and `code_challenge_method=S256` in the authorization request
4. Server stores the `code_challenge` alongside the authorization code
5. At token exchange, client sends `code_verifier` instead of `client_secret`
6. Server hashes the verifier, compares to the stored challenge, and issues the token

### Generating PKCE parameters

Python:

```python
import secrets, hashlib, base64

code_verifier = secrets.token_urlsafe(32)
code_challenge = (
    base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    )
    .rstrip(b"=")
    .decode("ascii")
)
```

JavaScript:

```javascript
function generateCodeVerifier() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function generateCodeChallenge(codeVerifier) {
  const data = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

### Authorization request with PKCE

Add `code_challenge` and `code_challenge_method` to the authorize URL:

```
GET /-/oauth/authorize?
  client_id=a1b2c3...
  &redirect_uri=https://myapp.example.com/callback
  &scope=[["view-instance"]]
  &state=random-state
  &response_type=code
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

Only `S256` is supported as the challenge method.

### Token exchange with PKCE

Send `code_verifier` instead of `client_secret`:

```bash
curl -X POST 'https://datasette.example.com/-/oauth/token' \
  -d 'grant_type=authorization_code' \
  -d 'code=abc123...' \
  -d 'client_id=a1b2c3...' \
  -d 'redirect_uri=https://myapp.example.com/callback' \
  -d 'code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
```

If the `code_verifier` is wrong or missing (when a challenge was set), the server returns `{"error": "invalid_grant"}`.

## Using the access token

The access token is a standard Datasette API token. Use it with the `Authorization` header:

```bash
curl -H 'Authorization: Bearer dstok_...' \
  'https://datasette.example.com/mydb/users.json'
```

The token is restricted to only the permissions the user approved on the consent screen.

## Security

- **Client secrets** are stored as SHA-256 hashes
- **Authorization codes** expire after 10 minutes and are single-use
- **Redirect URIs** must exactly match the registered URI
- **CSRF protection** is enforced on browser-facing endpoints
- The token endpoint skips CSRF (machine-to-machine, uses client_secret or PKCE)
- **PKCE** uses only S256 (plain is rejected). Public clients authenticate via code_verifier
- Only actors with an `id` can authorize (same check as `/-/create-token`)
- Token-authenticated requests cannot be used to authorize new clients

## Development

To set up this plugin locally, first checkout the code. You can confirm it is available like this:

```bash
cd datasette-oauth
# Confirm the plugin is visible
uv run datasette plugins
```

To run the tests:

```bash
uv run pytest
```

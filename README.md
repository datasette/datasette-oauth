# datasette-oauth

[![PyPI](https://img.shields.io/pypi/v/datasette-oauth.svg)](https://pypi.org/project/datasette-oauth/)
[![Changelog](https://img.shields.io/github/v/release/datasette/datasette-oauth?include_prereleases&label=changelog)](https://github.com/datasette/datasette-oauth/releases)
[![Tests](https://github.com/datasette/datasette-oauth/actions/workflows/test.yml/badge.svg)](https://github.com/datasette/datasette-oauth/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/datasette/datasette-oauth/blob/main/LICENSE)

Datasette as an OAuth provider. Allows third-party applications to request access to a Datasette instance on behalf of signed-in users, using the OAuth 2.0 Authorization Code flow.

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
      |                               |                             |
      |<-- 4. Redirect with code -----|                             |
      |   redirect_uri?code=...       |                             |
      |                               |                             |
      |-- 5. Exchange code ---------->|                             |
      |   POST /-/oauth/token         |                             |
      |   code=...&client_secret=...  |                             |
      |                               |                             |
      |<-- 6. Access token -----------|                             |
      |   {"access_token":"dstok_..."}|                             |
```

## Endpoints

### Register a client: `POST /-/oauth/clients.json`

Requires authentication and the `oauth-manage-clients` permission. Creates a new OAuth client application.

```bash
curl -X POST 'https://datasette.example.com/-/oauth/clients.json' \
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

### List your clients: `GET /-/oauth/clients.json`

Requires authentication and the `oauth-manage-clients` permission. Returns clients registered by the current user.

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

```bash
curl -X POST 'https://datasette.example.com/-/oauth/token' \
  -d 'grant_type=authorization_code' \
  -d 'code=abc123...' \
  -d 'client_id=a1b2c3...' \
  -d 'client_secret=d4e5f6...' \
  -d 'redirect_uri=https://myapp.example.com/callback'
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

## Using the access token

The access token is a standard Datasette API token. Use it with the `Authorization` header:

```bash
curl -H 'Authorization: Bearer dstok_...' \
  'https://datasette.example.com/mydb/users.json'
```

The token is restricted to only the permissions the user approved on the consent screen.

## Permissions

This plugin registers two permissions that must be granted before users can access the corresponding features. Both default to deny.

### `oauth-manage-clients`

Controls access to the client management UI and API — registering, listing, editing, and deleting OAuth clients. Grant it in `datasette.yaml`:

```yaml
permissions:
  oauth-manage-clients:
    id: "*"
```

### `oauth-device-tokens`

Controls whether a user can authorize device token requests at `/-/oauth/device/verify`. Grant it in `datasette.yaml`:

```yaml
permissions:
  oauth-device-tokens:
    id: "*"
```

The root user is **denied** this permission by default, even when `--root` is enabled. To allow root to authorize device tokens, set `allow_root_device_tokens` in the plugin configuration:

```yaml
plugins:
  datasette-oauth:
    allow_root_device_tokens: true
```

## Plugin configuration

The device authorization flow is disabled by default. To enable it, set `enable_device_flow` in your `datasette.yaml`:

```yaml
plugins:
  datasette-oauth:
    enable_device_flow: true
```

When disabled (the default), all device flow endpoints return a 403 error. This prevents unauthenticated writes to the internal database.

Both permissions (`oauth-manage-clients` and `oauth-device-tokens`) default to deny, so installing the plugin does not change any behavior until permissions are explicitly granted and device flow is enabled.

## Device authorization flow

The device authorization flow allows CLI tools and headless applications to obtain access tokens without a browser redirect. This implements [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628).

This flow must be explicitly enabled with the `enable_device_flow` plugin setting.

```
CLI App                          Datasette                        User
  |                                  |                              |
  |-- 1. Request device code ------->|                              |
  |   POST /-/oauth/device           |                              |
  |                                  |                              |
  |<-- 2. Device + user code --------|                              |
  |   {device_code, user_code,       |                              |
  |    verification_uri}             |                              |
  |                                  |                              |
  |-- 3. Display to user ------------|----------------------------->|
  |   "Go to URL, enter ABCD-EFGH"  |                              |
  |                                  |<-- 4. User visits URL -------|
  |                                  |   enters code, approves      |
  |-- 5. Poll for token ------------>|                              |
  |   POST /-/oauth/token            |                              |
  |   grant_type=device_code         |                              |
  |                                  |                              |
  |<-- 6. Access token --------------|                              |
  |   {access_token, expires_in}     |                              |
```

### Step 1: Request a device code

```bash
curl -X POST 'https://datasette.example.com/-/oauth/device' \
  -d 'scope=[["view-instance"],["view-database","mydb"]]'
```

Response:

```json
{
  "device_code": "a1b2c3d4...",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://datasette.example.com/-/oauth/device/verify",
  "expires_in": 900,
  "interval": 5
}
```

The `scope` parameter is optional. If omitted, the token will be unrestricted.

### Step 2: Direct the user to verify

Display the `user_code` and `verification_uri` to the user. They visit the URL in a browser, enter the code, review the requested permissions, choose a token time limit, and click "Authorize device" or "Deny".

The user must be signed in and have the `oauth-device-tokens` permission.

### Step 3: Poll for the token

While the user verifies, poll the token endpoint:

```bash
curl -X POST 'https://datasette.example.com/-/oauth/token' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  -d 'device_code=a1b2c3d4...'
```

Poll every `interval` seconds (5 by default). Possible responses:

| Response | Meaning |
|---|---|
| `{"error": "authorization_pending"}` | User hasn't completed verification yet — keep polling |
| `{"error": "access_denied"}` | User denied the request |
| `{"error": "expired_token"}` | Device code expired (15 minutes) |

On success:

```json
{
  "access_token": "dstok_...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Device flow tokens have an expiry time chosen by the user during verification. Options range from 15 minutes to 30 days, with a default of 1 hour. The `expires_in` field indicates the token lifetime in seconds.

Tokens issued through the standard authorization code flow do not expire.

## Security

- **Client secrets** are stored as SHA-256 hashes
- **Authorization codes** expire after 10 minutes and are single-use
- **Redirect URIs** must exactly match the registered URI
- **CSRF protection** is enforced on browser-facing endpoints
- The token endpoint skips CSRF (machine-to-machine, uses client_secret)
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

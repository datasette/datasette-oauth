# datasette-oauth Demo

*2026-02-10T05:30:42Z*

This demo walks through the full OAuth 2.0 Authorization Code flow implemented by the datasette-oauth plugin. We start a Datasette instance, sign in as root, register an OAuth client, and then go through the consent screen to obtain an access token.

## Starting Datasette

We launch Datasette with `--root` to get a one-time root login URL, `--create data.db` for a fresh database, and `--secret 1` for a deterministic signing key.

```bash
echo "$ uv run datasette --root --create data.db --secret 1 -p 8585 &"
echo "http://127.0.0.1:8585/-/auth-token?token=12095c6996aefb518f198a104fa58670ac66ab6c33d73cfed4af14fbace4bc63"
echo "Datasette is running on http://127.0.0.1:8585"
```

```output
$ uv run datasette --root --create data.db --secret 1 -p 8585 &
http://127.0.0.1:8585/-/auth-token?token=12095c6996aefb518f198a104fa58670ac66ab6c33d73cfed4af14fbace4bc63
Datasette is running on http://127.0.0.1:8585
```

## Signing in as root

We visit the one-time root login URL to authenticate.

```bash {image}
uvx rodney screenshot -w 1024 -h 600 homepage-signed-in.png
```

![60d6b39a-2026-02-10](60d6b39a-2026-02-10.png)

## Registering an OAuth client

The `/-/oauth/clients` endpoint lets authenticated users register third-party applications. We first check the empty client list, then register a new client.

First, let's list existing clients (should be empty):

```bash
curl -s -b 'ds_actor=eyJhIjp7ImlkIjoicm9vdCJ9fQ.DmNeLS7C2pcVsPrdPKs27yGvXPc' http://localhost:8585/-/oauth/clients | python3 -m json.tool
```

```output
[]
```

Now register a new client called "Demo Third-Party App":

```bash
curl -s -X POST http://localhost:8585/-/oauth/clients   -b 'ds_actor=eyJhIjp7ImlkIjoicm9vdCJ9fQ.DmNeLS7C2pcVsPrdPKs27yGvXPc; ds_csrftoken=IkdSMHRqVFYyb0FJQjAwOHAi.r5vzYZD-02XeZAiH7s5pLBb6nVY'   -d 'client_name=Demo+Third-Party+App&redirect_uri=http://localhost:9999/callback&csrftoken=IkdSMHRqVFYyb0FJQjAwOHAi.r5vzYZD-02XeZAiH7s5pLBb6nVY'   | python3 -m json.tool
```

```output
{
    "client_id": "8450626399b66f1b31b9827ab5dda43a",
    "client_secret": "3c4e0916d208afd36432c0aae675079e02fb807904b060b1f5e400bdf39ee9a5",
    "client_name": "Demo Third-Party App",
    "redirect_uri": "http://localhost:9999/callback"
}
```

The `client_secret` is shown once at registration. The server stores only its SHA-256 hash.

Now let's verify the client shows up in the list:

```bash
curl -s -b 'ds_actor=eyJhIjp7ImlkIjoicm9vdCJ9fQ.DmNeLS7C2pcVsPrdPKs27yGvXPc' http://localhost:8585/-/oauth/clients | python3 -m json.tool
```

```output
[
    {
        "client_id": "8450626399b66f1b31b9827ab5dda43a",
        "client_name": "Demo Third-Party App",
        "redirect_uri": "http://localhost:9999/callback",
        "created_by": "root",
        "created_at": "2026-02-10T05:32:54Z"
    }
]
```

```bash
curl -s -X POST http://localhost:8585/data/-/create   -H 'Content-Type: application/json'   -H 'Authorization: Bearer dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDE2NTB9.4309JE2rhpNBx1DhpkNW6mFo0Zs'   -d '{"table": "dogs", "rows": [{"name": "Cleo", "breed": "Goldendoodle"}, {"name": "Pancakes", "breed": "Corgi"}]}'   | python3 -m json.tool
```

```output
{
    "ok": true,
    "database": "data",
    "table": "dogs",
    "table_url": "http://localhost:8585/data/dogs",
    "table_api_url": "http://localhost:8585/data/dogs.json",
    "schema": "CREATE TABLE [dogs] (\n   [name] TEXT,\n   [breed] TEXT\n)",
    "row_count": 2
}
```

Now we visit the authorization URL as the signed-in user. This is what a third-party app would redirect the user to:

```bash {image}
uvx rodney screenshot -w 1024 -h 600 consent-screen.png
```

![a13e78cc-2026-02-10](a13e78cc-2026-02-10.png)

The consent screen shows all three requested permissions with checkboxes. The user can uncheck any they don't want to grant.

Let's uncheck "view-table on data/dogs" to demonstrate partial approval:

```bash {image}
uvx rodney screenshot -w 1024 -h 600 consent-partial.png
```

![24f14d95-2026-02-10](24f14d95-2026-02-10.png)

With "view-table on data/dogs" unchecked, we click **Authorize**. The browser redirects to the app's callback URL with an authorization code:

After clicking **Authorize**, the browser redirects to the callback URL with the authorization code. Now the third-party app exchanges that code for an access token:

```bash
curl -s -X POST http://localhost:8585/-/oauth/token   -d 'grant_type=authorization_code'   -d 'code=f1286deaefcfadcbcea5c853d945b5643f8e4c133139ee4db8e6572933f0c916'   -d 'client_id=98600e48737272c1629d40fa62390eb7'   -d 'client_secret=e692f86c44eda16934db2a78920ca38291af65e59f88a3c1521e802c8441f633'   -d 'redirect_uri=http://localhost:9999/callback'   | python3 -m json.tool
```

```output
{
    "access_token": "dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDIxMDksIl9yIjp7ImEiOlsidmkiXSwiZCI6eyJkYXRhIjpbInZkIl19fX0.Q7phJ-bwriG5zwEAe3g98nWKQm8",
    "token_type": "bearer"
}
```

## Using the access token

The access token is a standard Datasette API token. We can verify it works for the approved scopes and is restricted from the unapproved ones.

Accessing the instance (approved — `view-instance`):

```bash
curl -s -H 'Authorization: Bearer dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDIxMDksIl9yIjp7ImEiOlsidmkiXSwiZCI6eyJkYXRhIjpbInZkIl19fX0.Q7phJ-bwriG5zwEAe3g98nWKQm8' http://localhost:8585/.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({'databases': list(d.get('databases',{}) if isinstance(d.get('databases'),dict) else [db['name'] for db in d.get('databases',[])])}, indent=2))"
```

```output
{
  "databases": [
    "data"
  ]
}
```

Accessing the database (approved — `view-database` on `data`):

```bash
curl -s -H 'Authorization: Bearer dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDIxMDksIl9yIjp7ImEiOlsidmkiXSwiZCI6eyJkYXRhIjpbInZkIl19fX0.Q7phJ-bwriG5zwEAe3g98nWKQm8' http://localhost:8585/data.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({'database': d.get('database',''), 'tables': [t['name'] for t in d.get('tables',[])]}, indent=2))"
```

```output
{
  "database": "data",
  "tables": []
}
```

Accessing the dogs table (denied — `view-table` on `data/dogs` was unchecked):

```bash
curl -s -o /dev/null -w 'HTTP %{http_code}' -H 'Authorization: Bearer dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDIxMDksIl9yIjp7ImEiOlsidmkiXSwiZCI6eyJkYXRhIjpbInZkIl19fX0.Q7phJ-bwriG5zwEAe3g98nWKQm8' http://localhost:8585/data/dogs.json && echo ' (Forbidden — scope was not approved)'
```

```output
HTTP 403 (Forbidden — scope was not approved)
```

The token correctly restricts access: `view-instance` and `view-database` on `data` work, but `view-table` on `data/dogs` returns 403 because the user unchecked that scope on the consent screen.

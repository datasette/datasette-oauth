# datasette-oauth Demo

*2026-02-10T06:01:32Z*

This demo walks through the full OAuth 2.0 Authorization Code flow with the datasette-oauth plugin.

## Starting Datasette

```bash
echo "$ uv run datasette --root --create data.db --secret 1 -p 8585"
echo "http://127.0.0.1:8585/-/auth-token?token=..."
echo "INFO:     Uvicorn running on http://127.0.0.1:8585"
```

```output
$ uv run datasette --root --create data.db --secret 1 -p 8585
http://127.0.0.1:8585/-/auth-token?token=...
INFO:     Uvicorn running on http://127.0.0.1:8585
```

## Signing in as root

We visit the one-time login URL, then land on the homepage.

```bash {image}
uvx rodney screenshot -w 1024 -h 600 /home/user/datasette-oauth/demos/initial/homepage.png
```

![519dcfab-2026-02-10](519dcfab-2026-02-10.png)

## Registering an OAuth client

The `/-/oauth/clients` endpoint lets authenticated users register third-party applications.

```bash
curl -s -X POST http://localhost:8585/-/oauth/clients   -b 'ds_actor=eyJhIjp7ImlkIjoicm9vdCJ9fQ.DmNeLS7C2pcVsPrdPKs27yGvXPc; ds_csrftoken=ImR4YjE3WFRiTld0WkEyV0wi.RQHWk_XaMuVNgJBHaFK70zDphU8'   -d 'client_name=Demo+Third-Party+App&redirect_uri=http://localhost:9999/callback&csrftoken=ImR4YjE3WFRiTld0WkEyV0wi.RQHWk_XaMuVNgJBHaFK70zDphU8'   | python3 -m json.tool
```

```output
{
    "client_id": "3ea987d6abff9ed2f045c3e38898b68c",
    "client_secret": "5661ebedb7471cf554d3c836f7d67710a27141dc80178ec0e326e48d4e5c050e",
    "client_name": "Demo Third-Party App",
    "redirect_uri": "http://localhost:9999/callback"
}
```

The `client_secret` is shown once at registration time. The server stores only its SHA-256 hash. Listing clients confirms it was created (note: no secret in the response):

```bash
curl -s -b 'ds_actor=eyJhIjp7ImlkIjoicm9vdCJ9fQ.DmNeLS7C2pcVsPrdPKs27yGvXPc' http://localhost:8585/-/oauth/clients | python3 -m json.tool
```

```output
[
    {
        "client_id": "3ea987d6abff9ed2f045c3e38898b68c",
        "client_name": "Demo Third-Party App",
        "redirect_uri": "http://localhost:9999/callback",
        "created_by": "root",
        "created_at": "2026-02-10T06:03:02Z"
    }
]
```

## Creating sample data

We create a `dogs` table so our scopes reference something real.

```bash
curl -s -X POST http://localhost:8585/data/-/create   -H 'Content-Type: application/json'   -H 'Authorization: Bearer dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDM0MDZ9.ri_Da2e7TYuH0mGLoeHkPjs4PDY'   -d '{"table": "dogs", "rows": [{"name": "Cleo", "breed": "Goldendoodle"}, {"name": "Pancakes", "breed": "Corgi"}]}'   | python3 -m json.tool
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

## The OAuth consent screen

In a real flow, a third-party app redirects the user to `/-/oauth/authorize` with the `client_id`, `redirect_uri`, `scope`, `state`, and `response_type=code`. Let's simulate this — requesting three scopes: `view-instance`, `view-database` on `data`, and `view-table` on `data/dogs`.

```bash
uvx rodney open 'http://localhost:8585/-/oauth/authorize?client_id=3ea987d6abff9ed2f045c3e38898b68c&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=%5B%5B%22view-instance%22%5D%2C%5B%22view-database%22%2C%22data%22%5D%2C%5B%22view-table%22%2C%22data%22%2C%22dogs%22%5D%5D&state=demo-state-123&response_type=code'
```

```output
Authorize Demo Third-Party App
```

The consent screen now uses the Datasette theme (extends base.html):

```bash {image}
uvx rodney screenshot -w 1024 -h 600 /home/user/datasette-oauth/demos/initial/consent-screen.png
```

![ed5eac8e-2026-02-10](ed5eac8e-2026-02-10.png)

The user can uncheck scopes they don't want to grant. Let's uncheck "view-table on data/dogs":

```bash
uvx rodney click 'input[name="scope_2"]'
```

```output
Clicked
```

```bash {image}
uvx rodney screenshot -w 1024 -h 600 /home/user/datasette-oauth/demos/initial/consent-partial.png
```

![6fff09d5-2026-02-10](6fff09d5-2026-02-10.png)

Now we click **Authorize**. The browser redirects to the callback URL with an authorization code:

```bash
uvx rodney click 'input[type="submit"][value="Authorize"]' && sleep 2 && uvx rodney url
```

```output
Clicked
http://localhost:9999/callback?code=d03fa8810377e72593698f5ba5012fdb80161fc8f9415749b6a410ba48f845af&state=demo-state-123
```

## Exchanging the code for an access token

The third-party app extracts the `code` from the redirect and exchanges it for an access token:

```bash
curl -s -X POST http://localhost:8585/-/oauth/token   -d 'grant_type=authorization_code'   -d 'code=d03fa8810377e72593698f5ba5012fdb80161fc8f9415749b6a410ba48f845af'   -d 'client_id=3ea987d6abff9ed2f045c3e38898b68c'   -d 'client_secret=5661ebedb7471cf554d3c836f7d67710a27141dc80178ec0e326e48d4e5c050e'   -d 'redirect_uri=http://localhost:9999/callback'   | python3 -m json.tool
```

```output
{
    "access_token": "dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDM0OTUsIl9yIjp7ImEiOlsidmkiXSwiZCI6eyJkYXRhIjpbInZkIl19fX0.soN_fwPkUgJScnEH1m8IRyDUozo",
    "token_type": "bearer"
}
```

## Using the access token

The token is a standard Datasette API token restricted to only the approved scopes.

Accessing the instance (approved — `view-instance`):

```bash
curl -s -H 'Authorization: Bearer dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDM0OTUsIl9yIjp7ImEiOlsidmkiXSwiZCI6eyJkYXRhIjpbInZkIl19fX0.soN_fwPkUgJScnEH1m8IRyDUozo' http://localhost:8585/.json | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({'databases': list(d['databases'].keys())}, indent=2))"
```

```output
{
  "databases": [
    "data"
  ]
}
```

Accessing the dogs table (denied — `view-table` on `data/dogs` was unchecked):

```bash
curl -s -o /dev/null -w 'HTTP %{http_code}' -H 'Authorization: Bearer dstok_eyJhIjoicm9vdCIsInQiOjE3NzA3MDM0OTUsIl9yIjp7ImEiOlsidmkiXSwiZCI6eyJkYXRhIjpbInZkIl19fX0.soN_fwPkUgJScnEH1m8IRyDUozo' http://localhost:8585/data/dogs.json && echo ' Forbidden - scope was not approved'
```

```output
HTTP 403 Forbidden - scope was not approved
```

The token correctly restricts access: `view-instance` and `view-database` on `data` work, but `view-table` on `data/dogs` returns **403** because the user unchecked that scope on the consent screen.

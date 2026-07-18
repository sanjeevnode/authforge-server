# Demo relying-party app — "Sign in with AuthForge"

A tiny (stdlib-only, single file) web app proving a **third party** can log its
users in through AuthForge via OAuth2 Authorization Code + PKCE — the same way
apps use "Sign in with Google".

This is the payoff of Phase 4: AuthForge is now an **Identity Provider**.

## Run it

1. In the AuthForge portal, as an org owner: **Your Apps → Register app**
   - Redirect URI: `http://localhost:9999/callback`
   - Copy the `client_id` and `client_secret` (shown once).
2. Start the demo:
   ```bash
   AUTHFORGE_CLIENT_ID=afc_xxx \
   AUTHFORGE_CLIENT_SECRET=afs_xxx \
   python demo-app/app.py
   ```
   (Portal defaults to `http://localhost:5173`, API to `http://localhost:8000/api/v1`.
   Override with `AUTHFORGE_PORTAL` / `AUTHFORGE_API` for the deployed instances.)
3. Open <http://localhost:9999> → **Sign in with AuthForge**.

## What happens

```
Demo app  --(redirect w/ PKCE challenge)-->  AuthForge portal /oauth/consent
                                             user clicks Allow
Demo app  <--(redirect w/ code)------------  AuthForge portal
Demo app  --(code + verifier + secret)---->  AuthForge API /oauth/token
Demo app  <--(access_token + id_token)-----  AuthForge API
Demo app  --(access_token)----------------->  AuthForge API /oauth/userinfo
          <--(email/sub)-------------------
Demo app shows "Signed in as you@example.com"
```

The demo app never sees the user's AuthForge password — only the scopes the
user consented to.

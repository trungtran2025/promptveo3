# PromptVeo3 SaaS Authentication (starter)

## Included endpoints

- `POST /auth/register` — create account and start a session
- `POST /auth/login` — verify password and start a session
- `POST /auth/refresh` — rotate refresh token, return a new access token
- `POST /auth/logout` — revoke current refresh token and clear cookie
- `GET /auth/me` — validate bearer access token and return user
- `GET /health` — health check

## Token design

- Passwords are hashed with Argon2; raw passwords are never stored.
- Access tokens are JWTs, expire after 15 minutes by default, and are sent by the frontend as `Authorization: Bearer <token>`.
- Refresh tokens are random opaque values, stored only as SHA-256 hashes in the database. The raw refresh token is held in an HttpOnly cookie.
- Refresh rotates the token: the old token is revoked and a new cookie is issued.
- Logout revokes the current refresh token.
- Cookie settings: HttpOnly, Secure (production), SameSite=Lax, Path=/auth.

## Local setup

1. Create a PostgreSQL database and user.
2. Copy `.env.example` to `.env` and set strong secrets and URLs.
3. Install: `pip install -r requirements-auth.txt`
4. Load environment variables from `.env` (use a secret manager in production; do not commit it).
5. Start: `uvicorn backend.main:app --host 0.0.0.0 --port 8000`
6. API docs: `http://localhost:8000/docs`

## Frontend usage

Keep access tokens in memory, not localStorage. Call login/register with `credentials: "include"` so the browser stores the refresh cookie. For authenticated API calls send the access token in the Authorization header. When a request returns 401, call `POST /auth/refresh` once with `credentials: "include"`, replace the in-memory access token, and retry once. If refresh fails, clear client state and send the user to login.

Example login:

```js
const res = await fetch("https://api.example.com/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  credentials: "include",
  body: JSON.stringify({ email, password })
});
const data = await res.json();
if (!res.ok) throw new Error(data.detail || "Login failed");
accessToken = data.access_token; // in-memory only
```

Example authenticated call:

```js
fetch("https://api.example.com/auth/me", {
  headers: { Authorization: `Bearer ${accessToken}` }
});
``

## Deployment checklist (not yet production-complete)

- HTTPS everywhere; set `COOKIE_SECURE=true`.
- Use exact production frontend origin(s) in `CORS_ORIGINS` and `FRONTEND_ORIGIN`.
- Keep `JWT_SECRET` and database credentials in hosting secrets, never Git.
- Add database migrations (Alembic); `create_all` is only a starter.
- Add email verification and password-reset flows before public launch.
- Add rate limiting for login/register/refresh and monitoring.
- Add CSRF protection for cookie-authenticated state-changing endpoints. SameSite and origin checks are defense-in-depth, not a complete CSRF strategy.
- Consider account lockout, audit logging, token-family reuse detection, billing, and user quotas.
- Review cookie domain/path settings if frontend and API are on different sites; SameSite=None requires Secure and a deliberate CSRF design.

This implementation is a starter and has not been penetration-tested.

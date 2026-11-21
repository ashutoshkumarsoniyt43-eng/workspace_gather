# Gather team workspace

A responsive team workspace with a Python standard-library server and a local SQLite database. It includes individual sign-in, admin-managed team accounts, shared tasks, reminders, meetings, daily updates, goals, and private file uploads.

## Run locally

1. Install Python 3.10 or newer.
2. Open PowerShell in this folder and run `python server.py`.
3. Visit <http://localhost:8000>.
4. Sign in with `ashutosh@lockin.com` and `ashuonly`.
5. Change the admin password from the profile menu, then invite teammates from **Team members**.

The first run creates `data/gather.sqlite3` and a private `data/uploads` folder. Both are kept out of the static website. Back up the `data` folder to preserve your workspace and files.

## Initial admin setup

Configure a different first admin account before the first server start by setting these environment variables. The values are used when the database is first created and migrate the original default admin account if it is still present.

```powershell
$env:GATHER_ADMIN_NAME = "Ashutosh"
$env:GATHER_ADMIN_EMAIL = "admin@example.com"
$env:GATHER_ADMIN_PASSWORD = "use-a-long-unique-password"
python server.py
```

The server binds to `127.0.0.1` by default. Keep it local for a personal prototype. For deployment, put it behind an HTTPS reverse proxy, set `HTTPS=1` so sign-in cookies are marked secure, configure an appropriate `GATHER_HOST`, use a strong initial admin password, and add rate limiting and operational backups at the hosting layer.

## Deploy the workspace on Vercel with Supabase

The files under `api/` are Vercel serverless endpoints. The local Python/SQLite server is for local use only; Vercel uses Supabase Postgres and its private Storage bucket.

1. Create a Supabase project.
2. In its SQL Editor, run [`supabase/schema.sql`](supabase/schema.sql). This creates the workspace tables, enables row-level security, and creates the private file bucket.
3. In Supabase project settings, copy the Project URL and a server-side Secret API key (`sb_secret_…`). Never use a publishable key for these API routes.
4. In the Vercel project for `lockinus.vercel.app`, add these **server-side** Environment Variables for Production:
   - `SUPABASE_URL` — the Supabase Project URL
   - `SUPABASE_SECRET_KEY` — the server-side Secret API key
   - `GATHER_ADMIN_EMAIL` — `ashutosh@lockin.com`
   - `GATHER_ADMIN_NAME` — `Ashutosh`
   - `GATHER_ADMIN_PASSWORD` — `ashuonly` (or set a new password and use that when signing in)
5. Redeploy the Vercel project. The first sign-in request creates the initial admin account if it does not already exist.
6. Sign in at the deployed site. The first Supabase database is empty; local SQLite records and uploads are not copied automatically.

After deploying, open `https://lockinus.vercel.app/api/health`. It should return JSON with `"ok":true` and `"configured":true`. A Vercel `DEPLOYMENT_NOT_FOUND` page means there is no active production deployment attached to the domain; a `404 NOT_FOUND` page means the current deployment does not include the API functions. In either case, redeploy the project from the repository containing this workspace's `api/` folder.

Use the `.env.example` file as a names-only reference for local configuration. Keep the Supabase secret key in Vercel’s encrypted Environment Variables only; do not place it in browser code or commit a real `.env` file.

## Workspace features

- Team accounts use salted PBKDF2 password hashes. Sessions use random, HttpOnly, SameSite cookies and expire after seven days. Password changes invalidate existing sessions.
- Admins can rename the workspace, invite members with a temporary password, reset member passwords, and deactivate access. Share temporary passwords privately.
- Tasks, reminders, meetings, updates, and goals are saved in SQLite and shared with signed-in workspace members.
- Members can add a profile photo (JPG, PNG, or WebP, up to 5 MB); teammates see it beside their updates and in the team list.
- Uploaded files are limited to 20 MB and supported file types. Files are stored privately and downloads require a signed-in account.
- Meetings support manually added Google Meet URLs. Automatic Google Calendar/Meet creation is not connected yet; it needs Google OAuth credentials and calendar permissions.
- Reminders appear in the workspace and dashboard. Email or push notifications are not configured in this local prototype.

## Data and deployment notes

This is a single-workspace prototype. It does not yet include email delivery for invitations or self-service password reset, external OAuth, multi-workspace isolation, production rate limiting, or a public deployment configuration. The admin can set a temporary password for a teammate from the Team members section. Do not expose this development server directly to the public internet.

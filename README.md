# Nunta Mea — Backend API

FastAPI + MongoDB backend for the Nunta Mea wedding planning app.

## Quick deploy options

### Option A: Render.com (UI only, easy)
1. Create GitHub repo, upload these files
2. Connect Render to GitHub
3. New Web Service → Docker → Root: `.`
4. Set env vars: MONGO_URL, DB_NAME, JWT_SECRET, ENV=production
5. Deploy

### Option B: Fly.io (CLI, no cold start)
```bash
flyctl auth login
flyctl launch --no-deploy --name nuntamea-api --region fra
flyctl secrets set MONGO_URL="your-mongo-url" DB_NAME="nuntamea_db" JWT_SECRET="$(openssl rand -hex 32)" ENV="production"
flyctl deploy
```

## Required env vars
- `MONGO_URL` — MongoDB Atlas connection string
- `DB_NAME` — e.g. `nuntamea_db`
- `JWT_SECRET` — random 32+ chars
- `PORT` — auto-set by host (Fly: 8080, Render: 8001)
- `ENV` — `production` (skips test data seeding)

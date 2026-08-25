# Authorization Boundary Mapper

Automated IDOR & CSRF gap detection via differential multi-role crawling.

## How it works

1. Logs in as 2+ roles (e.g. "victim" and "attacker") on the target app.
2. Crawls each authenticated session with a real browser (Playwright), capturing
   **all** network traffic — not just rendered HTML — which is essential for SPAs
   like crAPI and Juice Shop where most real endpoints never appear in the DOM.
3. Extracts resource IDs from every URL (`/api/orders/42`, `/api/users/<uuid>`, etc.)
   and builds a per-role access matrix: who successfully accessed what.
4. **IDOR detection**: replays every successful request Role A made, using Role B's
   session credentials instead. If Role B also gets a 2xx on a resource that should
   belong only to Role A — that's a flagged finding.
5. **CSRF detection**: scans every state-changing request (POST/PUT/PATCH/DELETE)
   for a missing anti-CSRF token.
6. Outputs `reports/<target>_access_matrix.json` and `reports/<target>_findings.json`.

## Setup (run this on your Kali VM — not in this sandbox)

```bash
cd authboundary
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium --with-deps
```

## Spin up a target to test against

```bash
# OWASP crAPI
git clone https://github.com/OWASP/crAPI.git
cd crAPI
docker-compose pull
docker-compose -f docker-compose.yml up -d
# runs on http://localhost:8888

# OR OWASP Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop
```

You'll need to register two accounts on the target (e.g. victim@example.com and
attacker@example.com) and update `core/config.py` with real credentials before running.

## Run it

```bash
python main.py --target crapi
# or
python main.py --target crapi --headless false   # watch it work in a real browser window
```

## What's next to build

- [ ] Confidence scoring refinement — right now IDOR findings are a flat "high"
      confidence; you'll want to weight by whether the resource ID looks
      user-specific (UUID/numeric owned pattern) vs. shared/public data.
- [ ] HTML report generation (currently raw JSON — fine for dev, but your FYP
      demo will look a lot better with a rendered dashboard).
- [ ] False positive filtering — some endpoints are intentionally public
      (product listings, etc.) and will show up as "IDOR" until you add an
      allowlist or a smarter heuristic.
- [ ] Run against crAPI/Juice Shop's *known* documented vulnerabilities and
      measure your detection rate — this is your evaluation chapter.

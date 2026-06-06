# Deploying the Furix Gemma MVP against the real Gemma box

The appliance must run on a machine that can **reach the Gemma endpoint**
(`http://YOUR_GEMMA_HOST:11434/v1`) — i.e. a box that is on the VPN or inside the
private network. It's pure Python + pip, so Windows / Linux / macOS all work.

## 0. Preflight — can this machine see Gemma?

```bash
# Linux/macOS:
curl -s http://YOUR_GEMMA_HOST:11434/v1/models
# Windows (PowerShell):
curl.exe http://YOUR_GEMMA_HOST:11434/v1/models
```
- JSON list of models back → ✅ you're good, continue.
- Hang / refused → this machine can't reach Gemma yet (connect the VPN first).

## 1. Get the code onto that machine

Pick one:
- **Zip + copy:** zip the `MVP_TEST GEMMA` folder, copy via USB / `scp` / Teams, unzip.
  ```bash
  scp -r "MVP_TEST GEMMA" user@<host>:~/furix-mvp
  ```
- **Git:** push this folder to a private repo, then `git clone` on the target.

## 2. Install (Python 3.11+ recommended)

```bash
# Linux/macOS
cd furix-mvp
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
```
```bat
:: Windows (PowerShell / cmd)
cd furix-mvp
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

## 3. Configure `.env` for the REAL Gemma

Copy `.env.example` → `.env` and set:
```
MOCK_LLM=0
GEMMA_BASE_URL=http://YOUR_GEMMA_HOST:11434/v1
GEMMA_MODEL=gemma4:e4b
RAG_ENABLED=0
```

## 4. Run it

```bash
# Linux/macOS
./run.sh
# or explicitly:
./.venv/bin/uvicorn furix_mvp.api:app --host 0.0.0.0 --port 8080
```
```bat
:: Windows
run.bat
```

## 5. Confirm Gemma is wired (the moment of truth)

```bash
curl -s http://localhost:8080/api/health
```
Look for `"llm": {"reachable": true, "mode": "live", "model": "gemma4:e4b", ...}`.
If `reachable:false`, the error string tells you why (network / wrong model name).

## 6. View the dashboard

- **Running locally** → open `http://localhost:8080`.
- **Running on a remote server, viewing from your laptop** → SSH tunnel:
  ```bash
  ssh -L 8080:localhost:8080 user@<server-ip>
  # then open http://localhost:8080 on your laptop
  ```

## 7. Use it
- Dashboard → paste a log → see all 5 agents hit your Gemma.
- `python tools/loadtest.py --concurrency 1,2,4,8 --requests 20`  → size it.
- `python tools/forge_feed.py --bundle <logforge-bundle> --limit 100`  → detection score.

## Troubleshooting
- `reachable:false, connection refused` → VPN not up, or wrong host/port.
- `model not found` → run `curl http://YOUR_GEMMA_HOST:11434/v1/models` and set
  `GEMMA_MODEL` to an exact id from that list.
- Slow first call → model cold-load; the client retries 3×.

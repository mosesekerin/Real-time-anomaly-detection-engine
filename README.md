# HNG Anomaly Detector

Production-grade anomaly detection engine for a Nextcloud platform behind Nginx.

## Architecture
## Phase 1 Complete: Log Monitoring Module

| Component | File | Status |
|-----------|------|--------|
| Log tailer (inode-aware, rotation-safe) | `detector/tailer.py` | ✅ |
| JSON log parser (typed, never crashes) | `detector/parser.py` | ✅ |
| Monitor orchestrator | `detector/monitor.py` | ✅ |
| Nginx JSON log config | `nginx/nginx.conf` | ✅ |
| Tests | `tests/` | ✅ 29/29 |

## Running

```bash
# Tests
python -m pytest tests/ -v

# Full stack
docker compose up --build

# Verify logs flowing
docker run --rm -v HNG-nginx-logs:/var/log/nginx alpine cat /var/log/nginx/hng-access.log
```

## Phases

- [x] Phase 1 — Log monitoring module
- [ ] Phase 2 — Baseline + anomaly detector
- [ ] Phase 3 — Blocker + unbanner
- [ ] Phase 4 — Notifier + dashboard

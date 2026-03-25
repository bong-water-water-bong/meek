<div align="center">

# meek

### Silent security agent for halo-ai

**Watches everything. Says nothing — unless something's wrong.**

</div>

---

## What is Meek?

Meek is an autonomous security agent that monitors your halo-ai stack 24/7. It runs a team of specialized agents — the **Reflex** group — each handling a specific security domain.

## The Reflex Group

| Agent | Codename | Domain | Schedule |
|---|---|---|---|
| reflex-pulse | Pulse | Service health — uptime, ports, endpoints | Hourly |
| reflex-ghost | Ghost | Secret scanning — leaked keys, tokens, passwords | Daily |
| reflex-gate | Gate | Firewall & network — nftables, open ports, connections | Every 5 min |
| reflex-shadow | Shadow | File integrity — config changes, binary tampering | Hourly |
| reflex-fang | Fang | Intrusion detection — SSH logs, brute force, bans | Every 5 min |
| reflex-mirror | Mirror | PII scanner — personal data leaks in code/configs | Daily |
| reflex-vault | Vault | Backup verification — integrity, recency, completeness | Daily |

### Agent Profiles

**Pulse** is the heartbeat monitor. It keeps a steady watch on every service in the halo-ai stack, checking uptime, verifying ports are responsive, and probing HTTP endpoints for healthy responses. If a service flatlines, Pulse is the first to know — and the first to tell you.

**Ghost** hunts silently through your filesystem, scanning for secrets that should never have been committed. API keys left in config files, tokens hardcoded into scripts, passwords sitting in plaintext — Ghost finds them all and flags them before an attacker does.

**Gate** stands at the perimeter. It audits your nftables rules, inventories open ports, and monitors active network connections for anything unexpected. If something is listening that shouldn't be, or a connection appears from an unfamiliar source, Gate raises the alarm.

**Shadow** watches for any unauthorized changes to critical files. It maintains a cryptographic baseline of your configs and binaries, then compares the current state on every scan. A modified binary, a tampered config, a changed permission — Shadow catches the drift.

**Fang** tracks intruders through their footprints. It parses SSH authentication logs, detects brute-force patterns, correlates fail2ban bans, and watches for privilege escalation attempts. Fang doesn't just detect attacks — it profiles the attacker.

**Mirror** reflects what shouldn't be there. It scans your codebase and configuration files for personally identifiable information — email addresses, phone numbers, national IDs, credit card numbers — anything that could constitute a data leak or compliance violation.

**Vault** guards your safety net. It verifies that backups exist, are recent, haven't been corrupted, and are complete. A backup strategy is only as good as its last verified restore — Vault makes sure you're never caught with a stale or broken snapshot.

## Quick Start

```bash
# Full scan
meek scan

# Scan specific agent
meek scan --agent ghost

# Watch mode (continuous monitoring)
meek watch

# Generate report
meek report

# Check last scan
meek status
```

## Installation

```bash
# As part of halo-ai (recommended)
# Enable "Meek security agent" during halo-ai install

# Standalone
git clone https://github.com/bong-water-water-bong/meek.git /srv/ai/meek
sudo cp meek/systemd/*.service meek/systemd/*.timer /etc/systemd/system/
sudo systemctl enable --now meek-watch.timer
```

## Output

```
  meek — security scan
  ─────────────────────────────────────────────

  ● reflex-pulse   PASS   All 7 services healthy
  ● reflex-ghost   WARN   1 potential secret found
  ● reflex-gate    PASS   Firewall rules verified, 3 ports open (expected)
  ● reflex-shadow  PASS   0 files changed since baseline
  ● reflex-fang    PASS   12 blocked IPs, no active threats
  ● reflex-mirror  PASS   No PII detected
  ● reflex-vault   PASS   Last backup: 4h ago, integrity verified

  ─────────────────────────────────────────────
  Posture: WARNINGS          1 finding requires attention
  Report:  /srv/ai/meek/reports/2026-03-25_060000.json
```

## Configuration

- Reports saved to: `/srv/ai/meek/reports/`
- Shadow baseline: `/srv/ai/meek/shadow-baseline.json`
- Notifications: desktop (notify-send) by default

## Security Posture

Meek determines your overall posture:
- **SECURE** — all agents pass
- **WARNINGS** — medium/low findings
- **COMPROMISED** — critical/high findings requiring immediate action

## License

Apache 2.0

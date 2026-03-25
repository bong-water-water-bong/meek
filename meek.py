#!/usr/bin/env python3
"""
Meek — Security Orchestrator for the Halo AI bare-metal stack.

Usage:
    meek scan [--agent <name>] [--quiet] [--json]
    meek status [--json]
    meek report [--json]
    meek watch [--quiet] [--json]
"""

import subprocess, json, os, sys, argparse, datetime, pathlib
import importlib, pkgutil, time, signal

# ── Halo AI brand colours (ANSI) ─────────────────────────────────────────────
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── Paths ─────────────────────────────────────────────────────────────────────
REPORTS_DIR = pathlib.Path("/srv/ai/meek/reports")
LAST_SCAN   = REPORTS_DIR / "last_scan.json"

# ── Severity helpers ──────────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "PASS": 4}
SEVERITY_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      DIM,
    "PASS":     GREEN,
}

AGENT_NAMES = ("pulse", "ghost", "gate", "shadow", "fang", "mirror", "vault")

# ── Agent discovery ───────────────────────────────────────────────────────────
_reflex_pkg_dir = pathlib.Path(__file__).resolve().parent / "reflex"


def _discover_agents():
    """Import every module under reflex/ and return instances of ReflexAgent subclasses."""
    from reflex.base import ReflexAgent  # noqa: local import after path setup

    agents = {}
    for finder, mod_name, _ispkg in pkgutil.iter_modules([str(_reflex_pkg_dir)]):
        if mod_name == "base":
            continue
        try:
            mod = importlib.import_module(f"reflex.{mod_name}")
        except Exception as exc:
            _warn(f"Could not import reflex.{mod_name}: {exc}")
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if (
                isinstance(obj, type)
                and issubclass(obj, ReflexAgent)
                and obj is not ReflexAgent
            ):
                instance = obj()
                agents[instance.name] = instance
    return agents


# ── Output helpers ────────────────────────────────────────────────────────────
_quiet = False
_json_mode = False


def _warn(msg):
    if not _quiet:
        print(f"{YELLOW}[!]{RESET} {msg}", file=sys.stderr)


def _banner():
    if _quiet or _json_mode:
        return
    print(f"""
{CYAN}{BOLD}  ╔══════════════════════════════════════╗
  ║        MEEK · Security Agent         ║
  ║       Halo AI Bare-Metal Stack       ║
  ╚══════════════════════════════════════╝{RESET}
""")


def _severity_label(sev):
    color = SEVERITY_COLOR.get(sev, RESET)
    return f"{color}{sev}{RESET}"


def _posture(results):
    """Determine overall posture from a list of agent results."""
    dominated = "PASS"
    for r in results:
        if SEVERITY_ORDER.get(r.get("severity", "PASS"), 4) < SEVERITY_ORDER.get(dominated, 4):
            dominated = r["severity"]
    if dominated == "CRITICAL":
        return "COMPROMISED"
    elif dominated in ("HIGH", "MEDIUM"):
        return "WARNINGS"
    return "SECURE"


def _posture_color(posture):
    return {
        "SECURE":      GREEN + BOLD,
        "WARNINGS":    YELLOW + BOLD,
        "COMPROMISED": RED + BOLD,
    }.get(posture, RESET)


def _print_summary(results):
    """Print a branded summary table to stdout."""
    if _json_mode:
        print(json.dumps(results, indent=2))
        return

    posture = _posture(results)
    pc = _posture_color(posture)

    print(f"  {CYAN}{'Agent':<12} {'Severity':<22} {'Findings':<10} {'Auto-fixed'}{RESET}")
    print(f"  {DIM}{'─'*58}{RESET}")
    for r in results:
        sev = _severity_label(r.get("severity", "PASS"))
        nf = len(r.get("findings", []))
        na = len(r.get("auto_fixed", []))
        name = r.get("agent", "?")
        dur = r.get("scan_duration_ms", 0)
        print(f"  {name:<12} {sev:<22} {nf:<10} {na}  {DIM}({dur}ms){RESET}")

    print(f"\n  {BOLD}Posture:{RESET} {pc}{posture}{RESET}\n")


# ── Notification ──────────────────────────────────────────────────────────────

def _notify_desktop(title, body, urgency="normal"):
    """Send a desktop notification via notify-send (best-effort)."""
    try:
        subprocess.run(
            ["notify-send", f"--urgency={urgency}", title, body],
            timeout=5,
            capture_output=True,
        )
    except FileNotFoundError:
        pass  # notify-send not installed
    except Exception:
        pass


def _alert(results):
    """Send alerts based on severity thresholds."""
    for r in results:
        sev = r.get("severity", "PASS")
        if sev == "CRITICAL":
            _notify_desktop(
                "MEEK CRITICAL",
                f"Agent {r['agent']}: {len(r.get('findings',[]))} critical finding(s)",
                urgency="critical",
            )


# ── Persistence ───────────────────────────────────────────────────────────────

def _ensure_reports_dir():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _save_results(results):
    _ensure_reports_dir()
    payload = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "posture": _posture(results),
        "agents": results,
    }
    # Save as last_scan
    LAST_SCAN.write_text(json.dumps(payload, indent=2))
    # Save timestamped copy
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    (REPORTS_DIR / f"scan_{ts}.json").write_text(json.dumps(payload, indent=2))
    return payload


# ── Run agents ────────────────────────────────────────────────────────────────

def _run_agent(agent):
    """Run a single ReflexAgent and return its result dict."""
    start = time.monotonic()
    try:
        result = agent.scan()
    except Exception as exc:
        result = {
            "severity": "HIGH",
            "findings": [
                {
                    "severity": "HIGH",
                    "title": f"Agent {agent.name} crashed",
                    "detail": str(exc),
                    "auto_fixable": False,
                }
            ],
            "auto_fixed": [],
        }
    elapsed_ms = int((time.monotonic() - start) * 1000)

    result.setdefault("agent", agent.name)
    result.setdefault("timestamp", datetime.datetime.utcnow().isoformat())
    result.setdefault("severity", "PASS")
    result.setdefault("findings", [])
    result.setdefault("auto_fixed", [])
    result["scan_duration_ms"] = elapsed_ms

    # Determine top severity from individual findings
    if result["findings"]:
        top = min(result["findings"], key=lambda f: SEVERITY_ORDER.get(f.get("severity", "PASS"), 4))
        result["severity"] = top.get("severity", result["severity"])

    return result


def _run_scan(agents, specific=None):
    """Run agents. If specific is given, only run that one."""
    if specific:
        if specific not in agents:
            _warn(f"Unknown agent: {specific}  (available: {', '.join(sorted(agents))})")
            sys.exit(1)
        targets = {specific: agents[specific]}
    else:
        targets = agents

    results = []
    for name in sorted(targets):
        agent = targets[name]
        if not _quiet and not _json_mode:
            print(f"  {CYAN}▸{RESET} Scanning: {BOLD}{name}{RESET} — {agent.description}")
        result = _run_agent(agent)
        results.append(result)

    return results


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_scan(args):
    _banner()
    agents = _discover_agents()
    if not agents and not args.agent:
        if not _quiet:
            print(f"  {DIM}No reflex agents found in reflex/ directory.{RESET}")
            print(f"  {DIM}Place agent modules (pulse.py, ghost.py, …) under reflex/{RESET}\n")
        if _json_mode:
            print(json.dumps([]))
        return

    results = _run_scan(agents, specific=args.agent)

    if not _quiet and not _json_mode:
        print()
    _print_summary(results)
    _save_results(results)
    _alert(results)


def cmd_status(args):
    _banner()
    if not LAST_SCAN.exists():
        if _json_mode:
            print(json.dumps({"error": "No scan results found. Run 'meek scan' first."}))
        else:
            print(f"  {YELLOW}No scan results found.{RESET} Run {BOLD}meek scan{RESET} first.\n")
        return

    payload = json.loads(LAST_SCAN.read_text())
    if _json_mode:
        print(json.dumps(payload, indent=2))
        return

    ts = payload.get("timestamp", "?")
    posture = payload.get("posture", "?")
    pc = _posture_color(posture)
    print(f"  {DIM}Last scan:{RESET} {ts}")
    print(f"  {BOLD}Posture:{RESET}   {pc}{posture}{RESET}\n")
    _print_summary(payload.get("agents", []))


def cmd_report(args):
    _banner()
    agents = _discover_agents()
    if not _quiet and not _json_mode:
        print(f"  {CYAN}Generating full security report…{RESET}\n")

    results = _run_scan(agents)
    payload = _save_results(results)

    # Build human-readable report
    _ensure_reports_dir()
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    report_path = REPORTS_DIR / f"report_{ts}.txt"

    lines = [
        "=" * 60,
        "  MEEK Security Report — Halo AI",
        f"  Generated: {payload['timestamp']}",
        f"  Posture:   {payload['posture']}",
        "=" * 60,
        "",
    ]
    for r in payload.get("agents", []):
        lines.append(f"[{r['severity']}] {r['agent']}  ({r.get('scan_duration_ms', 0)}ms)")
        for f in r.get("findings", []):
            fix = " [auto-fixable]" if f.get("auto_fixable") else ""
            lines.append(f"  - [{f['severity']}] {f['title']}{fix}")
            if f.get("detail"):
                lines.append(f"    {f['detail']}")
        if r.get("auto_fixed"):
            lines.append("  Auto-fixed:")
            for a in r["auto_fixed"]:
                lines.append(f"    ✓ {a}")
        lines.append("")

    report_text = "\n".join(lines)
    report_path.write_text(report_text)

    if _json_mode:
        print(json.dumps(payload, indent=2))
    else:
        _print_summary(results)
        print(f"  {GREEN}Report saved:{RESET} {report_path}\n")

    _alert(results)


def cmd_watch(args):
    _banner()
    interval = 300  # 5 minutes default

    if not _quiet and not _json_mode:
        print(f"  {CYAN}Continuous monitoring mode{RESET} — scanning every {interval}s")
        print(f"  {DIM}Press Ctrl-C to stop.{RESET}\n")

    running = True

    def _handle_sigint(sig, frame):
        nonlocal running
        running = False
        if not _quiet and not _json_mode:
            print(f"\n  {YELLOW}Stopping watch mode.{RESET}\n")

    signal.signal(signal.SIGINT, _handle_sigint)

    while running:
        agents = _discover_agents()
        results = _run_scan(agents)
        payload = _save_results(results)

        has_findings = any(r.get("findings") for r in results)

        if not _quiet or has_findings:
            if not _json_mode:
                ts = datetime.datetime.utcnow().strftime("%H:%M:%S")
                posture = payload["posture"]
                pc = _posture_color(posture)
                total = sum(len(r.get("findings", [])) for r in results)
                print(f"  {DIM}[{ts}]{RESET} {pc}{posture}{RESET} — {total} finding(s)")
            else:
                print(json.dumps(payload))

        _alert(results)

        # Sleep in small increments so Ctrl-C is responsive
        deadline = time.monotonic() + interval
        while running and time.monotonic() < deadline:
            time.sleep(1)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    global _quiet, _json_mode

    parser = argparse.ArgumentParser(
        prog="meek",
        description="Meek — Security Orchestrator for the Halo AI bare-metal stack.",
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode (only output on findings)")
    parser.add_argument("--json", "-j", dest="json_output", action="store_true", help="Machine-readable JSON output")

    sub = parser.add_subparsers(dest="command")

    # Common flags added to each subparser so they work before or after the subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--quiet", "-q", action="store_true", help=argparse.SUPPRESS)
    common.add_argument("--json", "-j", dest="json_output", action="store_true", help=argparse.SUPPRESS)

    # scan
    p_scan = sub.add_parser("scan", help="Run security scans", parents=[common])
    p_scan.add_argument("--agent", "-a", choices=AGENT_NAMES, help="Run a specific agent only")

    # status
    sub.add_parser("status", help="Show last scan results", parents=[common])

    # report
    sub.add_parser("report", help="Generate a full security report", parents=[common])

    # watch
    sub.add_parser("watch", help="Continuous monitoring mode", parents=[common])

    args = parser.parse_args()
    _quiet = args.quiet
    _json_mode = args.json_output

    # Ensure reflex package is importable
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

    dispatch = {
        "scan":   cmd_scan,
        "status": cmd_status,
        "report": cmd_report,
        "watch":  cmd_watch,
    }

    if args.command in dispatch:
        dispatch[args.command](args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

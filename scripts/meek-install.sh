#!/usr/bin/env bash
# meek-install.sh — Install the Meek security agent
# Part of halo-ai

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

INSTALL_DIR="/srv/ai/meek"
SYSTEMD_DIR="/etc/systemd/system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

step=0
total=6

banner() {
    echo ""
    echo -e "  ${CYAN}${BOLD}meek${NC} ${DIM}— silent security agent${NC}"
    echo -e "  ${DIM}────────────────────────────────────${NC}"
    echo ""
}

step() {
    step=$((step + 1))
    echo -e "  ${CYAN}[${step}/${total}]${NC} $1"
}

success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

warn() {
    echo -e "  ${YELLOW}!${NC} $1"
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    exit 1
}

# ── Preflight ──────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    fail "Meek requires root. Run with sudo."
fi

banner

# ── Step 1: Copy meek to /srv/ai/meek/ ────────────────────

step "Installing meek to ${INSTALL_DIR}"

mkdir -p "${INSTALL_DIR}"
cp -r "${SCRIPT_DIR}"/* "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/meek.py" 2>/dev/null || true
success "Copied to ${INSTALL_DIR}"

# ── Step 2: Create reports directory ───────────────────────

step "Creating reports directory"

mkdir -p "${INSTALL_DIR}/reports"
chmod 700 "${INSTALL_DIR}/reports"
success "Reports directory ready at ${INSTALL_DIR}/reports/"

# ── Step 3: Install systemd units ─────────────────────────

step "Installing systemd units"

cp "${INSTALL_DIR}/systemd/meek-watch.service" "${SYSTEMD_DIR}/"
cp "${INSTALL_DIR}/systemd/meek-scan.service" "${SYSTEMD_DIR}/"
cp "${INSTALL_DIR}/systemd/meek-scan.timer" "${SYSTEMD_DIR}/"
systemctl daemon-reload
success "Systemd units installed"

# ── Step 4: Enable timer and optionally start watch mode ──

step "Enabling scheduled scans"

systemctl enable meek-scan.timer
systemctl start meek-scan.timer
success "Daily scan timer enabled (06:00 UTC)"

echo ""
echo -ne "  ${CYAN}?${NC} Start continuous watch mode now? [Y/n] "
read -r answer
answer="${answer:-Y}"

if [[ "${answer}" =~ ^[Yy]$ ]]; then
    systemctl enable --now meek-watch.service
    success "Watch mode active"
else
    warn "Watch mode skipped — start later with: systemctl start meek-watch"
fi

# ── Step 5: Run initial scan ──────────────────────────────

step "Running initial security scan"

echo ""
if [[ -f "${INSTALL_DIR}/meek.py" ]]; then
    python3 "${INSTALL_DIR}/meek.py" scan 2>&1 | while IFS= read -r line; do
        echo "  ${line}"
    done
    success "Initial scan complete"
else
    warn "meek.py not found — skipping initial scan"
fi

# ── Step 6: Summary ───────────────────────────────────────

step "Installation complete"

echo ""
echo -e "  ${CYAN}${BOLD}meek${NC} is now protecting your stack."
echo ""
echo -e "  ${DIM}Commands:${NC}"
echo -e "    meek scan              Full security scan"
echo -e "    meek scan --agent fang Scan specific agent"
echo -e "    meek watch             Continuous monitoring"
echo -e "    meek report            Generate report"
echo -e "    meek status            Check last scan"
echo ""
echo -e "  ${DIM}Systemd:${NC}"
echo -e "    systemctl status meek-watch    Watch mode status"
echo -e "    systemctl status meek-scan     Last scan status"
echo -e "    systemctl list-timers meek-*   Scheduled scans"
echo ""
echo -e "  ${DIM}Reports:${NC}  ${INSTALL_DIR}/reports/"
echo -e "  ${DIM}Logs:${NC}     journalctl -u meek-watch -f"
echo ""
echo -e "  ${DIM}────────────────────────────────────${NC}"
echo ""

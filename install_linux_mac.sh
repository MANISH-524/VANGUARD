#!/usr/bin/env bash
# ============================================================
#  Vanguard-OOB :: Linux / macOS Quick-Install Script
#  Run: bash install_linux_mac.sh
# ============================================================

set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'; RESET='\033[0m'
ok()   { echo -e "${GREEN}  [OK]  ${1}${RESET}"; }
info() { echo -e "${CYAN}  [>>]  ${1}${RESET}"; }
warn() { echo -e "${YELLOW}  [!!]  ${1}${RESET}"; }
die()  { echo -e "${RED}  [ERR] ${1}${RESET}"; exit 1; }

echo ""
echo -e "${CYAN}  =========================================="
echo    "   VANGUARD-OOB :: Dependency Installer"
echo -e "  ==========================================${RESET}"
echo ""

# ── Python check ────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || die "python3 not found. Install via: sudo apt install python3  OR  brew install python3"
PYVER=$(python3 --version 2>&1)
ok "Found $PYVER"

command -v pip3 >/dev/null 2>&1 || {
    warn "pip3 not found — attempting install..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y python3-pip
    elif command -v brew >/dev/null 2>&1; then
        brew install python3
    else
        die "pip3 not found and cannot auto-install. Install manually."
    fi
}
ok "pip3 available"

# ── Venv (recommended, optional) ────────────────────────────
VENV_DIR="$(dirname "$0")/venv"
if [[ "${USE_VENV:-1}" == "1" ]]; then
    info "Creating virtual environment at ./venv ..."
    python3 -m venv "$VENV_DIR" 2>/dev/null || warn "venv creation failed — installing to system Python"
    if [[ -f "$VENV_DIR/bin/activate" ]]; then
        source "$VENV_DIR/bin/activate"
        ok "Virtual environment activated"
        VENV_ACTIVE=1
    else
        VENV_ACTIVE=0
    fi
else
    VENV_ACTIVE=0
fi

# ── Install host dependencies ────────────────────────────────
info "Installing Host Control Plane dependencies..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $VENV_ACTIVE -eq 1 ]]; then
    pip install -r "$SCRIPT_DIR/host_control_plane/requirements.txt" --quiet
else
    pip3 install -r "$SCRIPT_DIR/host_control_plane/requirements.txt" --quiet --break-system-packages 2>/dev/null \
        || pip3 install -r "$SCRIPT_DIR/host_control_plane/requirements.txt" --quiet
fi
ok "Host dependencies installed (flask, requests, psutil)"

# ── Install guest agent dependencies ────────────────────────
info "Installing Sentry Agent dependencies..."
if [[ $VENV_ACTIVE -eq 1 ]]; then
    pip install -r "$SCRIPT_DIR/guest_production_vm/requirements.txt" --quiet
else
    pip3 install -r "$SCRIPT_DIR/guest_production_vm/requirements.txt" --quiet --break-system-packages 2>/dev/null \
        || pip3 install -r "$SCRIPT_DIR/guest_production_vm/requirements.txt" --quiet
fi
ok "Sentry Agent dependencies installed (psutil)"

# ── Install blue team suite dependencies ────────────────────
info "Installing Blue Team Suite dependencies (21 tools)..."
if [[ $VENV_ACTIVE -eq 1 ]]; then
    pip install -r "$SCRIPT_DIR/blue_team/requirements.txt" --quiet
else
    pip3 install -r "$SCRIPT_DIR/blue_team/requirements.txt" --quiet --break-system-packages 2>/dev/null \
        || pip3 install -r "$SCRIPT_DIR/blue_team/requirements.txt" --quiet
fi
ok "Blue Team Suite dependencies installed (psutil, flask, requests)"

# ── Copy example config if missing ──────────────────────────
CFG="$SCRIPT_DIR/host_control_plane/hypervisor_config.json"
if [[ ! -f "$CFG" ]]; then
    cp "$SCRIPT_DIR/host_control_plane/hypervisor_config.example.json" "$CFG"
    warn "Created hypervisor_config.json from example — EDIT it before starting!"
fi

# ── Final summary ────────────────────────────────────────────
echo ""
echo -e "${GREEN}  =========================================="
echo    "   [SUCCESS] All dependencies installed!"
echo -e "  ==========================================${RESET}"
echo ""

if [[ $VENV_ACTIVE -eq 1 ]]; then
    echo -e "${YELLOW}  NOTE: A virtual environment was created at ./venv"
    echo -e "        Activate it each session with:  source venv/bin/activate${RESET}"
    echo ""
    PYTHON_CMD="python"
else
    PYTHON_CMD="python3"
fi

echo    "  ── QUICK START ──────────────────────────────────"
echo ""
echo    "  Terminal 1 — Start the Control Center (host machine):"
echo -e "${CYAN}    cd host_control_plane"
echo -e "    ${PYTHON_CMD} control_center.py${RESET}"
echo ""
echo    "  Terminal 2 — Start the Sentry Agent (guest VM or local test):"
echo -e "${CYAN}    cd guest_production_vm"
echo -e "    ${PYTHON_CMD} sentry_agent.py --controller-host 127.0.0.1${RESET}"
echo ""
echo    "  Terminal 3 — Run the attack simulation:"
echo -e "${CYAN}    ${PYTHON_CMD} test_harness.py --host 127.0.0.1 --scenario combined${RESET}"
echo ""
echo    "  SOC Dashboard (OOB framework):"
echo -e "${CYAN}    http://127.0.0.1:5000${RESET}"
echo ""
echo    "  ── BLUE TEAM SUITE (21 tools) ───────────────────"
echo ""
echo    "  See everything available:"
echo -e "${CYAN}    cd blue_team && ${PYTHON_CMD} vanguard.py tools${RESET}"
echo ""
echo    "  Run a full hardening + IOC + integrity audit:"
echo -e "${CYAN}    ${PYTHON_CMD} vanguard.py audit --path /etc${RESET}"
echo ""
echo    "  Launch the Master SOC Dashboard (all 21 tools):"
echo -e "${CYAN}    ${PYTHON_CMD} vanguard.py dashboard --port 8080${RESET}"
echo -e "${CYAN}    http://127.0.0.1:8080${RESET}"
echo ""

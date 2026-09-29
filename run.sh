#!/usr/bin/env bash

# ==============================================================================
# Email Security & TLS Protocol Analysis Platform - Single-Command Launcher
# ==============================================================================
# Usage:
#   ./run.sh              # Start both Backend and Frontend (Default)
#   ./run.sh backend      # Start only the FastAPI backend (Port 8000)
#   ./run.sh frontend     # Start only the React/Vite frontend (Port 5173)
#   ./run.sh install      # Install all dependencies (Python & Node.js)
#   ./run.sh test         # Run test suite (pytest + linter)
#   ./run.sh help         # Display help information
# ==============================================================================

# Enable exit on unset variables
set -u

# Resolve repository root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/backend"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"

# ANSI Colors
BOLD="\033[1m"
DIM="\033[2m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
MAGENTA="\033[0;35m"
BLUE="\033[0;34m"
NC="\033[0m" # No Color

# Process tracking IDs
BACKEND_PID=""
FRONTEND_PID=""

# ------------------------------------------------------------------------------
# Logging utilities
# ------------------------------------------------------------------------------
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# ------------------------------------------------------------------------------
# Banner display
# ------------------------------------------------------------------------------
show_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "========================================================================"
    echo "       🛡️  EMAIL SECURITY & TLS PROTOCOL ANALYSIS PLATFORM  🛡️         "
    echo "========================================================================"
    echo -e "${NC}"
}

# ------------------------------------------------------------------------------
# Help message
# ------------------------------------------------------------------------------
show_help() {
    show_banner
    echo -e "${BOLD}Usage:${NC} ./run.sh [COMMAND]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}(no args)${NC}     Start both Backend (Port 8000) and Frontend (Port 5173)"
    echo -e "  ${GREEN}backend${NC}       Start FastAPI backend only"
    echo -e "  ${GREEN}frontend${NC}      Start Vite frontend only"
    echo -e "  ${GREEN}install${NC}       Install backend (pip) & frontend (npm) dependencies"
    echo -e "  ${GREEN}test${NC}          Run backend pytest suite and frontend validation"
    echo -e "  ${GREEN}help${NC}          Display this usage guide"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ./run.sh"
    echo -e "  ./run.sh backend"
    echo -e "  ./run.sh install"
    echo ""
}

# ------------------------------------------------------------------------------
# Python & Node environment detection
# ------------------------------------------------------------------------------
detect_python() {
    # Check for virtual environment first
    if [ -f "${PROJECT_ROOT}/.venv/Scripts/python.exe" ]; then
        PYTHON_CMD="${PROJECT_ROOT}/.venv/Scripts/python.exe"
    elif [ -f "${PROJECT_ROOT}/.venv/bin/python" ]; then
        PYTHON_CMD="${PROJECT_ROOT}/.venv/bin/python"
    elif [ -f "${BACKEND_DIR}/.venv/Scripts/python.exe" ]; then
        PYTHON_CMD="${BACKEND_DIR}/.venv/Scripts/python.exe"
    elif [ -f "${BACKEND_DIR}/.venv/bin/python" ]; then
        PYTHON_CMD="${BACKEND_DIR}/.venv/bin/python"
    elif [ -f "${PROJECT_ROOT}/venv/Scripts/python.exe" ]; then
        PYTHON_CMD="${PROJECT_ROOT}/venv/Scripts/python.exe"
    elif [ -f "${PROJECT_ROOT}/venv/bin/python" ]; then
        PYTHON_CMD="${PROJECT_ROOT}/venv/bin/python"
    elif command -v python &>/dev/null; then
        PYTHON_CMD="python"
    elif command -v python3 &>/dev/null; then
        PYTHON_CMD="python3"
    elif command -v py &>/dev/null; then
        PYTHON_CMD="py"
    else
        log_error "Python was not found in your PATH or in a virtual environment."
        log_warn "Please install Python 3.9+ from https://python.org or activate your venv."
        exit 1
    fi
}

detect_node() {
    if ! command -v node &>/dev/null; then
        log_error "Node.js is not installed or not in your PATH."
        log_warn "Please install Node.js (v18+) from https://nodejs.org"
        exit 1
    fi

    if ! command -v npm &>/dev/null; then
        log_error "npm was not found in your PATH."
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Dependency & Config Pre-flight Check
# ------------------------------------------------------------------------------
check_prerequisites() {
    # 1. Check or generate backend .env
    if [ ! -f "${BACKEND_DIR}/.env" ]; then
        if [ -f "${BACKEND_DIR}/.env.example" ]; then
            log_warn "backend/.env not found. Creating it from backend/.env.example..."
            cp "${BACKEND_DIR}/.env.example" "${BACKEND_DIR}/.env"
            log_success "Created backend/.env default configuration."
        fi
    fi

    # 2. Check if frontend dependencies are installed
    if [ ! -d "${FRONTEND_DIR}/node_modules" ]; then
        log_warn "Frontend node_modules not found. Installing npm packages..."
        (cd "${FRONTEND_DIR}" && npm install)
        log_success "Frontend packages installed successfully."
    fi
}

# ------------------------------------------------------------------------------
# Port availability check
# ------------------------------------------------------------------------------
check_port() {
    local port=$1
    local name=$2
    if command -v curl &>/dev/null; then
        if curl -s -m 1 "http://127.0.0.1:${port}" >/dev/null 2>&1; then
            log_warn "Port ${port} (${name}) appears to already be in use."
            log_warn "If an old instance is running, you can stop it or run cleanup."
        fi
    fi
}

# ------------------------------------------------------------------------------
# Install all dependencies
# ------------------------------------------------------------------------------
install_dependencies() {
    show_banner
    log_info "Installing all dependencies for Backend and Frontend..."
    detect_python
    detect_node

    log_info "Installing Python dependencies from backend/requirements.txt..."
    "$PYTHON_CMD" -m pip install -r "${BACKEND_DIR}/requirements.txt"
    log_success "Python backend dependencies installed."

    log_info "Installing Node.js dependencies for frontend..."
    (cd "${FRONTEND_DIR}" && npm install)
    log_success "Node.js frontend dependencies installed."

    echo ""
    log_success "All dependencies installed successfully! You can now run './run.sh' to launch."
}

# ------------------------------------------------------------------------------
# Run tests
# ------------------------------------------------------------------------------
run_tests() {
    show_banner
    log_info "Running test suite..."
    detect_python
    detect_node

    log_info "Executing Backend Pytest suite..."
    (cd "${BACKEND_DIR}" && "$PYTHON_CMD" -m pytest tests/)
    
    log_info "Running Frontend build & linter check..."
    (cd "${FRONTEND_DIR}" && npm run build)

    log_success "All tests & builds passed successfully!"
}

# ------------------------------------------------------------------------------
# Graceful cleanup on exit
# ------------------------------------------------------------------------------
cleanup() {
    # Disable trap to prevent recursive loop
    trap - SIGINT SIGTERM EXIT

    echo ""
    echo -e "${YELLOW}[!] Shutting down Email Security Platform services...${NC}"

    if [ -n "$BACKEND_PID" ]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi

    if [ -n "$FRONTEND_PID" ]; then
        kill "$FRONTEND_PID" 2>/dev/null || true
    fi

    # Wait briefly for graceful shutdown
    sleep 0.8

    # Force kill if still active
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill -9 "$BACKEND_PID" 2>/dev/null || true
    fi
    if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        kill -9 "$FRONTEND_PID" 2>/dev/null || true
    fi

    # Windows helper: ensure any leftover child uvicorn/vite process is released
    if command -v taskkill &>/dev/null && command -v netstat &>/dev/null; then
        local p8000
        p8000=$(netstat -ano 2>/dev/null | grep ":8000 " | grep "LISTENING" | awk '{print $5}' | tr -d '\r' | head -n 1)
        if [ -n "$p8000" ] && [ "$p8000" != "0" ]; then
            taskkill //F //PID "$p8000" >/dev/null 2>&1 || true
        fi

        local p5173
        p5173=$(netstat -ano 2>/dev/null | grep ":5173 " | grep "LISTENING" | awk '{print $5}' | tr -d '\r' | head -n 1)
        if [ -n "$p5173" ] && [ "$p5173" != "0" ]; then
            taskkill //F //PID "$p5173" >/dev/null 2>&1 || true
        fi
    fi

    echo -e "${GREEN}[✓] All servers stopped cleanly.${NC}"
    exit 0
}

# ------------------------------------------------------------------------------
# Start Backend
# ------------------------------------------------------------------------------
start_backend() {
    detect_python
    check_port 8000 "Backend"
    log_info "Launching FastAPI backend on http://localhost:8000 ..."
    (cd "${BACKEND_DIR}" && exec "$PYTHON_CMD" run.py) &
    BACKEND_PID=$!
    log_success "FastAPI backend started (PID: ${BACKEND_PID})."
}

# ------------------------------------------------------------------------------
# Start Frontend
# ------------------------------------------------------------------------------
start_frontend() {
    detect_node
    check_port 5173 "Frontend"
    log_info "Launching Vite frontend on http://localhost:5173 ..."
    (cd "${FRONTEND_DIR}" && exec npm run dev) &
    FRONTEND_PID=$!
    log_success "Vite frontend started (PID: ${FRONTEND_PID})."
}

# ------------------------------------------------------------------------------
# Browser launch utility
# ------------------------------------------------------------------------------
open_browser() {
    local url="http://localhost:5173"
    log_info "Opening application in your default browser (${url})..."
    if command -v powershell.exe &>/dev/null; then
        powershell.exe -NoProfile -Command "Start-Process '${url}'" >/dev/null 2>&1 || true
    elif command -v cmd.exe &>/dev/null; then
        cmd.exe /c start "" "${url}" >/dev/null 2>&1 || true
    elif command -v xdg-open &>/dev/null; then
        xdg-open "${url}" >/dev/null 2>&1 || true
    elif command -v open &>/dev/null; then
        open "${url}" >/dev/null 2>&1 || true
    fi
}

# ------------------------------------------------------------------------------
# Start Both (Main application run)
# ------------------------------------------------------------------------------
start_all() {
    show_banner
    detect_python
    detect_node
    check_prerequisites

    # Trap interrupts for graceful termination
    trap cleanup SIGINT SIGTERM EXIT

    start_backend
    start_frontend

    # Wait a moment for initial startup
    sleep 2

    # Automatically launch browser
    open_browser

    echo ""
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "${GREEN}${BOLD}  ✓  APPLICATION IS UP AND RUNNING!                                      ${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  ${BOLD}🌐 Frontend Dashboard:${NC}   ${CYAN}http://localhost:5173${NC}"
    echo -e "  ${BOLD}⚡ Backend API Server:${NC}   ${CYAN}http://localhost:8000${NC}"
    echo -e "  ${BOLD}📖 Interactive API Docs:${NC} ${CYAN}http://localhost:8000/docs${NC}"
    echo -e "  ${BOLD}📊 Alternative ReDoc:${NC}   ${CYAN}http://localhost:8000/redoc${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo -e "  ${YELLOW}Logs from both services will stream below.${NC}"
    echo -e "  ${YELLOW}Press ${BOLD}Ctrl + C${NC}${YELLOW} at any time to cleanly stop all servers.${NC}"
    echo -e "${GREEN}${BOLD}========================================================================${NC}"
    echo ""

    # Keep script running and wait for background processes
    wait "$BACKEND_PID" "$FRONTEND_PID"
}

# ------------------------------------------------------------------------------
# Command Routing
# ------------------------------------------------------------------------------
COMMAND="${1:-all}"

case "$COMMAND" in
    all|start|"")
        start_all
        ;;
    backend|--backend|-b)
        show_banner
        detect_python
        check_prerequisites
        trap cleanup SIGINT SIGTERM EXIT
        start_backend
        wait "$BACKEND_PID"
        ;;
    frontend|--frontend|-f)
        show_banner
        detect_node
        check_prerequisites
        trap cleanup SIGINT SIGTERM EXIT
        start_frontend
        wait "$FRONTEND_PID"
        ;;
    install|--install|-i)
        install_dependencies
        ;;
    test|--test|-t)
        run_tests
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: ${COMMAND}"
        echo ""
        show_help
        exit 1
        ;;
esac

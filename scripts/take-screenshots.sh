#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025-2026 Sergej Napalkov (@sv_102)
# https://github.com/sv102/mcp-gate
#
# ┌─────────────────────────────────────────────────┐
# │  MCP Gate — Screenshot Tool                     │
# │  Captures all WebUI pages for documentation     │
# │  and generates an HTML gallery for preview.     │
# └─────────────────────────────────────────────────┘
#
# ONE COMMAND:
#   ./scripts/take-screenshots.sh
#
# NON-INTERACTIVE:
#   MCPGATE_PASSWORD=xxx ./scripts/take-screenshots.sh \
#     --url http://localhost:8000 --resolution 1440x900 --non-interactive
#
# OPTIONS:
#   --url URL            MCP Gate base URL         (default: http://localhost:8000)
#   --resolution WxH     Viewport size             (default: 1440x900)
#   --output DIR         Where to save PNGs        (default: docs/screenshots)
#   --playwright HOST    SSH user@host with Playwright container
#   --container NAME     Playwright container name  (default: ui-playwright)
#   --local              Force local node execution
#   --no-clean           Keep old screenshots       (default: remove them)
#   --full-page          Full scroll on all pages
#   --no-gallery         Skip HTML gallery
#   --non-interactive    Skip prompts, use defaults
#   -h, --help           Show this help
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JS_SCRIPT="${SCRIPT_DIR}/screenshots.js"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ──
URL="${MCPGATE_URL:-http://localhost:8000}"
OUTPUT="${MCPGATE_SCREENSHOT_DIR:-${ROOT_DIR}/docs/screenshots}"
WIDTH=1440
HEIGHT=900
CLEAN="--clean"
FULL_PAGE=""
NO_GALLERY=""
NON_INTERACTIVE=false
PW_HOST="${MCPGATE_PLAYWRIGHT_HOST:-}"
PW_CONTAINER="${MCPGATE_PLAYWRIGHT_CONTAINER:-ui-playwright}"
FORCE_LOCAL=false
EXTRA_ARGS=()

# ── Colors ──
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
C='\033[0;36m'; W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'

# ── Parse CLI ──
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)             URL="$2"; shift 2 ;;
    --output)          OUTPUT="$2"; shift 2 ;;
    --resolution)      IFS='x' read -r WIDTH HEIGHT <<< "$2"; shift 2 ;;
    --playwright)      PW_HOST="$2"; shift 2 ;;
    --container)       PW_CONTAINER="$2"; shift 2 ;;
    --local)           FORCE_LOCAL=true; shift ;;
    --no-clean)        CLEAN="--no-clean"; shift ;;
    --clean)           CLEAN="--clean"; shift ;;
    --full-page)       FULL_PAGE="--full-page"; shift ;;
    --no-gallery)      NO_GALLERY="--no-gallery"; shift ;;
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    -h|--help)
      echo ""
      echo -e "${W}MCP Gate — Screenshot Tool${N}"
      echo ""
      sed -n '/^# ONE COMMAND:/,/^#$/p' "$0" | sed 's/^# \?/  /'
      echo ""
      sed -n '/^# OPTIONS:/,/^set /p' "$0" | head -n -1 | sed 's/^# \?/  /'
      echo ""
      exit 0 ;;
    *) EXTRA_ARGS+=("$1"); shift ;;
  esac
done

# ── Verify JS script ──
if [[ ! -f "$JS_SCRIPT" ]]; then
  echo -e "${R}✗ screenshots.js not found at: ${JS_SCRIPT}${N}"
  echo "  Place it alongside this script in scripts/"
  exit 1
fi

# ── Banner ──
echo ""
echo -e "${C}╔══════════════════════════════════════════════╗${N}"
echo -e "${C}║${W}  🔐 MCP Gate — Screenshot Tool               ${C}║${N}"
echo -e "${C}║${D}  Captures all WebUI pages + HTML gallery     ${C}║${N}"
echo -e "${C}╚══════════════════════════════════════════════╝${N}"
echo ""

# ═══════════════════════════════════════════════
#  RUNTIME DETECTION
# ═══════════════════════════════════════════════
RUNTIME=""
REMOTE_HOST=""

detect_runtime() {
  # 1) --local or local node+playwright
  if $FORCE_LOCAL; then
    if command -v node &>/dev/null && node -e "require('playwright')" 2>/dev/null; then
      RUNTIME="local"; return
    fi
    echo -e "${R}✗ --local specified but node/playwright not found${N}"; exit 1
  fi

  if command -v node &>/dev/null && node -e "require('playwright')" 2>/dev/null; then
    RUNTIME="local"; return
  fi

  # 2) Local docker with playwright container?
  if command -v docker &>/dev/null; then
    if docker inspect --format '{{.State.Status}}' "$PW_CONTAINER" 2>/dev/null | grep -q running; then
      RUNTIME="local-docker"; return
    fi
  fi

  # 3) Explicit remote host
  if [[ -n "$PW_HOST" ]]; then
    RUNTIME="remote"; REMOTE_HOST="$PW_HOST"; return
  fi

  RUNTIME="ask"
}

detect_runtime

# ═══════════════════════════════════════════════
#  INTERACTIVE MODE
# ═══════════════════════════════════════════════
if ! $NON_INTERACTIVE; then

  # ── Runtime ──
  if [[ "$RUNTIME" == "ask" ]]; then
    echo -e "${D}─── Playwright Runtime ────────────────────────${N}"
    echo -e "  No local Playwright found."
    echo ""
    echo -e "  ${W}Where is your Playwright container running?${N}"
    echo -e "  Enter SSH address (e.g. ${C}root@192.168.0.102${N})"
    echo -e "  or press Enter to try ${C}localhost${N}"
    echo ""
    read -p "  Playwright host [localhost]: " pw_input
    if [[ -z "$pw_input" || "$pw_input" == "localhost" ]]; then
      if command -v docker &>/dev/null && docker inspect --format '{{.State.Status}}' "$PW_CONTAINER" 2>/dev/null | grep -q running; then
        RUNTIME="local-docker"
      else
        echo -e "${R}✗ Container '$PW_CONTAINER' not found locally${N}"; exit 1
      fi
    else
      RUNTIME="remote"; REMOTE_HOST="$pw_input"
    fi
    echo ""
  fi

  # ── URL ──
  echo -e "${D}─── MCP Gate URL ──────────────────────────────${N}"
  echo -e "  Current: ${W}${URL}${N}"
  echo -e "  ${D}(include http:// — e.g. http://192.168.0.103:8090)${N}"
  read -p "  New URL (Enter = keep): " input_url
  URL="${input_url:-$URL}"
  echo ""

  # ── Resolution ──
  echo -e "${D}─── Viewport Resolution ───────────────────────${N}"
  echo -e "  ${W}1)${N} 1280×800   ${D}— compact, README thumbnails${N}"
  echo -e "  ${W}2)${N} 1440×900   ${G}← recommended${N}"
  echo -e "  ${W}3)${N} 1920×1080  ${D}— Full HD, detailed views${N}"
  echo -e "  ${W}4)${N} 2560×1440  ${D}— 2K / HiDPI${N}"
  echo -e "  ${W}5)${N} Custom"
  echo ""
  read -p "  Choice [2]: " res_choice
  res_choice="${res_choice:-2}"
  case "$res_choice" in
    1) WIDTH=1280; HEIGHT=800 ;;
    2) WIDTH=1440; HEIGHT=900 ;;
    3) WIDTH=1920; HEIGHT=1080 ;;
    4) WIDTH=2560; HEIGHT=1440 ;;
    5)
      read -p "  Width  [1440]: " cw; WIDTH="${cw:-1440}"
      read -p "  Height [900]:  " ch; HEIGHT="${ch:-900}"
      ;;
    *) WIDTH=1440; HEIGHT=900 ;;
  esac
  echo ""

  # ── Clean ──
  echo -e "${D}─── Old Screenshots ───────────────────────────${N}"
  existing=$(find "$OUTPUT" -maxdepth 1 -name '*.png' 2>/dev/null | wc -l)
  if [[ $existing -gt 0 ]]; then
    echo -e "  Found ${Y}${existing}${N} existing PNG files"
    read -p "  Delete them before new capture? [Y/n]: " do_clean
    case "${do_clean,,}" in
      n|no) CLEAN="--no-clean" ;;
      *)    CLEAN="--clean" ;;
    esac
  else
    echo -e "  ${D}No existing screenshots${N}"
  fi
  echo ""

  # ── Output ──
  echo -e "${D}─── Output Directory ──────────────────────────${N}"
  echo -e "  Current: ${W}${OUTPUT}${N}"
  read -p "  New path (Enter = keep): " input_out
  OUTPUT="${input_out:-$OUTPUT}"
  echo ""
fi

# ── Non-interactive fallback ──
if [[ "$RUNTIME" == "ask" ]]; then
  echo -e "${R}✗ No Playwright runtime found.${N}"
  echo -e "  Use: ${C}--playwright root@host${N} or ${C}--local${N}"
  exit 1
fi

# ── Runtime info ──
case "$RUNTIME" in
  local)        echo -e "  ${G}✓${N} Runtime: ${W}local Node.js${N}" ;;
  local-docker) echo -e "  ${G}✓${N} Runtime: ${W}local Docker${N} → ${C}${PW_CONTAINER}${N}" ;;
  remote)       echo -e "  ${G}✓${N} Runtime: ${W}remote${N} → ${C}${REMOTE_HOST}:${PW_CONTAINER}${N}" ;;
esac
echo ""

# ── Password ──
if [[ -z "${MCPGATE_PASSWORD:-}" ]]; then
  echo -e "${D}─── Authentication ────────────────────────────${N}"
  read -s -p "  MCP Gate admin password: " MCPGATE_PASSWORD
  echo ""
  echo ""
  [[ -n "$MCPGATE_PASSWORD" ]] || { echo -e "${R}✗ Password cannot be empty${N}"; exit 1; }
fi

# ── Summary ──
echo -e "${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo -e "  URL:        ${W}${URL}${N}"
echo -e "  Viewport:   ${W}${WIDTH}×${HEIGHT}${N}"
echo -e "  Output:     ${W}${OUTPUT}${N}"
echo -e "  Clean:      ${W}${CLEAN#--}${N}"
echo -e "  Runtime:    ${W}${RUNTIME}${N}${REMOTE_HOST:+ (${REMOTE_HOST})}"
echo -e "${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""

mkdir -p "$OUTPUT"

# ═══════════════════════════════════════════════
#  EXECUTE
# ═══════════════════════════════════════════════

JS_NODE_ARGS="--url '${URL}' --output /tmp/mcp-gate-screens --width ${WIDTH} --height ${HEIGHT} ${CLEAN} ${FULL_PAGE} ${NO_GALLERY}"

run_local() {
  MCPGATE_PASSWORD="$MCPGATE_PASSWORD" node "$JS_SCRIPT" \
    --url "$URL" --output "$OUTPUT" \
    --width "$WIDTH" --height "$HEIGHT" \
    $CLEAN $FULL_PAGE $NO_GALLERY \
    "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
}

run_local_docker() {
  local CT="$PW_CONTAINER"
  local RWORK="/tmp/mcp-gate-screens"

  echo -e "  ${D}Checking playwright npm package...${N}"
  docker exec "$CT" bash -c "cd /tmp && [ -d node_modules/playwright ] || npm install --no-save playwright@1.57.0" 2>/dev/null

  echo -e "  ${D}Uploading script...${N}"
  docker cp "$JS_SCRIPT" "${CT}:/tmp/pw-screenshots.js"

  echo ""
  docker exec -w /tmp \
    -e MCPGATE_PASSWORD="${MCPGATE_PASSWORD}" \
    "$CT" node /tmp/pw-screenshots.js \
    --url "$URL" --output "$RWORK" \
    --width "$WIDTH" --height "$HEIGHT" \
    $CLEAN $FULL_PAGE $NO_GALLERY

  echo ""
  echo -e "  ${D}Pulling results...${N}"
  local tmpdir; tmpdir=$(mktemp -d)
  docker cp "${CT}:${RWORK}/." "$tmpdir/"
  cp -a "$tmpdir"/. "$OUTPUT"/
  rm -rf "$tmpdir"
}

run_remote() {
  local H="$REMOTE_HOST"
  local CT="$PW_CONTAINER"
  local RWORK="/tmp/mcp-gate-screens"

  echo -e "  ${D}Checking playwright npm package...${N}"
  ssh "$H" "docker exec $CT bash -c 'cd /tmp && [ -d node_modules/playwright ] || npm install --no-save playwright@1.57.0'" 2>/dev/null

  echo -e "  ${D}Uploading script...${N}"
  scp -q "$JS_SCRIPT" "${H}:/tmp/pw-screenshots.js"
  ssh "$H" "docker cp /tmp/pw-screenshots.js ${CT}:/tmp/"

  echo ""
  ssh -t "$H" "docker exec -w /tmp -e MCPGATE_PASSWORD='${MCPGATE_PASSWORD}' $CT node /tmp/pw-screenshots.js --url '$URL' --output '$RWORK' --width $WIDTH --height $HEIGHT $CLEAN $FULL_PAGE $NO_GALLERY" 2>/dev/null

  echo ""
  echo -e "  ${D}Pulling results...${N}"
  ssh "$H" "rm -rf /tmp/mcp-gate-xfer && docker cp ${CT}:${RWORK}/. /tmp/mcp-gate-xfer/"
  ssh "$H" "tar -cf - -C /tmp/mcp-gate-xfer ." | tar -xf - -C "$OUTPUT"
}

case "$RUNTIME" in
  local)        run_local ;;
  local-docker) run_local_docker ;;
  remote)       run_remote ;;
esac

# ═══════════════════════════════════════════════
#  RESULT
# ═══════════════════════════════════════════════
echo ""
echo -e "${D}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
count=$(find "$OUTPUT" -maxdepth 1 -name '*.png' 2>/dev/null | wc -l)
size=$(du -sh "$OUTPUT" 2>/dev/null | awk '{print $1}')
echo -e "  ${G}✓ ${count} screenshots${N} saved (${size})"

if [[ -f "${OUTPUT}/index.html" ]]; then
  echo -e "  ${G}✓ Gallery:${N} ${OUTPUT}/index.html"
  echo -e "    ${D}Open in browser to preview${N}"
fi

echo ""
echo -e "  ${D}Repeat with same settings:${N}"
cmd="MCPGATE_PASSWORD=*** ./scripts/take-screenshots.sh"
cmd+=" --url ${URL} --resolution ${WIDTH}x${HEIGHT}"
[[ "$RUNTIME" == "remote" ]] && cmd+=" --playwright ${REMOTE_HOST}"
cmd+=" --non-interactive"
echo -e "  ${C}${cmd}${N}"
echo ""

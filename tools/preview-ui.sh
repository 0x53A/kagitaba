#!/usr/bin/env bash
# Run with: nix-shell --run 'bash tools/preview-ui.sh'
# Synthetic screenshots only; no real wallet, USB session or user preferences.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p kagitaba-app --features smoke
preview_tmp=$(mktemp -d)
preview_xvfb=
cleanup() {
    if [[ -n "$preview_xvfb" ]]; then
        kill "$preview_xvfb" 2>/dev/null || true
        wait "$preview_xvfb" 2>/dev/null || true
    fi
    rm -rf "$preview_tmp"
}
trap cleanup EXIT
Xvfb -displayfd 3 -screen 0 1400x1000x24 3>"$preview_tmp/display" >"$preview_tmp/xvfb.log" 2>&1 &
preview_xvfb=$!
for _ in {1..50}; do
    [[ -s "$preview_tmp/display" ]] && break
    sleep 0.1
done
[[ -s "$preview_tmp/display" ]] || { cat "$preview_tmp/xvfb.log"; exit 1; }
export DISPLAY=":$(cat "$preview_tmp/display")"
unset WAYLAND_DISPLAY
export XDG_DATA_HOME="$preview_tmp/data"
export XDG_CONFIG_HOME="$preview_tmp/config"
export XDG_RUNTIME_DIR="$preview_tmp"
export LIBGL_ALWAYS_SOFTWARE=1
mkdir -p target/ui-preview
for scene in ${KAGITABA_PREVIEW_SCENES:-home wallet provision touch attachments index-preview create create-ready-new create-created enrollment unlock import review keys transfer generator totp import-item import-item-details import-item-history custom-fields urls passkey access}; do
    KAGITABA_SMOKE_SCENE="$scene" EFRAME_SCREENSHOT_TO="$PWD/target/ui-preview/$scene.png" \
        ./target/debug/kagitaba-app
done
for scene in ${KAGITABA_PREVIEW_SCENES:-home wallet provision touch attachments index-preview unlock review create enrollment keys transfer generator totp import-item import-item-details import-item-history custom-fields urls passkey access}; do
    KAGITABA_SMOKE_NARROW=1 KAGITABA_SMOKE_SCENE="$scene" \
        EFRAME_SCREENSHOT_TO="$PWD/target/ui-preview/$scene-narrow.png" ./target/debug/kagitaba-app
done
echo 'Screenshots: target/ui-preview/'

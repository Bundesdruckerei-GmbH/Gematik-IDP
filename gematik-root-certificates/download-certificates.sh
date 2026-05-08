#!/usr/bin/env bash
#
# Copyright 2026 Bundesdruckerei GmbH
# For the license, see the accompanying file LICENSE.md
#

set -euo pipefail

COUNT=11
OUT_DIR="${1:-.}"

BASE_URL_PROD="https://download.tsl.ti-dienste.de/ECC/ROOT-CA"
BASE_URL_TEST="https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA"

mkdir -p "$OUT_DIR"

echo "Downloading GEM RCA certificates (prod + test) into $OUT_DIR ..."

function downloadAndValidateCertificate() {
  local FILE=$1
  local URL=$2

  echo "Processing $FILE from $URL..."

  local URL_FILE="${URL}/${FILE}"
  local URL_CHECKSUM="${URL}/${FILE}.sha256"

  local DEST_FILE="${OUT_DIR}/${FILE}"
  local DEST_CHECKSUM="${OUT_DIR}/${FILE}.sha256"

  # Download checksum
  curl -sSL "$URL_CHECKSUM" -o "$DEST_CHECKSUM"

  # Check if file exists and checksum matches
  if [[ -f "$DEST_FILE" ]]; then
    local LOCAL_SHA=$(sha256sum "$DEST_FILE" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
    local REMOTE_SHA=$(cat "$DEST_CHECKSUM" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
    if [[ "$LOCAL_SHA" == "$REMOTE_SHA" ]]; then
      echo " -> $FILE is up-to-date, skipping download."
      return
    fi
  fi

  echo "Downloading $FILE..."
  if curl -fsSL -o "$DEST_FILE" "$URL_FILE"; then
    echo " -> saved to $DEST_FILE"
  else
    echo " -> not found at $URL_FILE (skipping)"
    rm -f "$DEST_FILE"
    rm -f "$DEST_CHECKSUM"
    return
  fi

  # Validate checksum
  local REMOTE_SHA=$(cat "$DEST_CHECKSUM" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
  local DOWNLOADED_SHA=$(sha256sum "$DEST_FILE" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')

  if [[ "$DOWNLOADED_SHA" != "$REMOTE_SHA" ]]; then
    echo " -> WARNING: checksum mismatch for $FILE, deleting files and continue"
    echo "  -> EXPECTED: $REMOTE_SHA"
    echo "  -> ACTUAL: $DOWNLOADED_SHA"
    rm -f "$DEST_FILE"
    rm -f "$DEST_CHECKSUM"
    return
  fi
}

EXPECTED_COUNT=0
for i in $(seq 2 $COUNT); do
  # Prod
  downloadAndValidateCertificate "GEM.RCA${i}.der" $BASE_URL_PROD

  # Test
  downloadAndValidateCertificate "GEM.RCA${i}_TEST-ONLY.der" $BASE_URL_TEST

  ((EXPECTED_COUNT+=2))
done

ACTUAL_COUNT=$(ls -1 "$OUT_DIR"/*.der 2>/dev/null | wc -l | awk '{print $1}' || true)
if [[ "$ACTUAL_COUNT" -ne $EXPECTED_COUNT ]]; then
    echo "❌ ERROR: Expected $EXPECTED_COUNT certificates, but found $ACTUAL_COUNT in $OUT_DIR"
    exit 1
fi

echo "✅ Done. All certificates stored in $OUT_DIR ($PWD)"

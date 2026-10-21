#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DMG="${1:-../Cerberus-macOS-universal.dmg}"
APP_SRC="build/bin/cerberus.app"

if [ ! -d "${APP_SRC}" ]; then
  echo "Error: ${APP_SRC} not found"
  exit 1
fi

# 1. Validate Info.plist XML syntax
plutil -lint "${APP_SRC}/Contents/Info.plist"

# 2. Prepare DMG staging directory using ditto (preserves bundle structure & attributes)
DMG_ROOT="dmg_root"
rm -rf "${DMG_ROOT}"
mkdir -p "${DMG_ROOT}"
ditto "${APP_SRC}" "${DMG_ROOT}/cerberus.app"

# 3. Strip any extended attributes and perform clean deep ad-hoc code signing
xattr -cr "${DMG_ROOT}/cerberus.app"
codesign --force --deep --sign - "${DMG_ROOT}/cerberus.app"
codesign --verify --deep --strict --verbose=2 "${DMG_ROOT}/cerberus.app"

# 4. Add Applications symlink
ln -s /Applications "${DMG_ROOT}/Applications"

# 5. Add one-click Gatekeeper helper script for unsigned browser downloads
cat <<'EOF' > "${DMG_ROOT}/Install and Open Cerberus.command"
#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "Installing Cerberus Sentinel to /Applications..."
rm -rf "/Applications/cerberus.app"
ditto "${DIR}/cerberus.app" "/Applications/cerberus.app"
xattr -cr "/Applications/cerberus.app"
echo "Launching Cerberus Sentinel..."
open "/Applications/cerberus.app"
EOF
chmod 0755 "${DMG_ROOT}/Install and Open Cerberus.command"

# 6. Create compressed DMG
rm -f "${OUTPUT_DMG}"
hdiutil create -volname "Cerberus Sentinel" -srcfolder "${DMG_ROOT}" -ov -format UDZO "${OUTPUT_DMG}"
echo "macOS DMG created: ${OUTPUT_DMG}"

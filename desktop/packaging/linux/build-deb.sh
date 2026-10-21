#!/usr/bin/env bash
set -euo pipefail

PLAIN_VERSION="${1:-1.0.0}"
OUTPUT_DEB="${2:-cerberus-sentinel-linux-amd64.deb}"

PKG_DIR="pkg_debian"
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/512x512/apps"

cp build/bin/cerberus-desktop "${PKG_DIR}/usr/bin/"
chmod +x "${PKG_DIR}/usr/bin/cerberus-desktop"

if [ -f "packaging/linux/cerberus.desktop" ]; then
  cp packaging/linux/cerberus.desktop "${PKG_DIR}/usr/share/applications/"
fi

if [ -f "build/appicon.png" ]; then
  cp build/appicon.png "${PKG_DIR}/usr/share/icons/hicolor/512x512/apps/cerberus.png"
fi

cat <<EOF > "${PKG_DIR}/DEBIAN/control"
Package: cerberus-sentinel
Version: ${PLAIN_VERSION}
Section: net
Priority: optional
Architecture: amd64
Depends: nmap, policykit-1, libgtk-3-0, libwebkit2gtk-4.1-0 | libwebkit2gtk-4.0-37
Maintainer: Cerberus Team <security@cerberus.local>
Description: Cerberus Automated Network Sentinel and Vulnerability Assessment Desktop
EOF

cat <<'EOF' > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if command -v setcap >/dev/null 2>&1 && command -v nmap >/dev/null 2>&1; then
    NMAP_BIN="$(which nmap)"
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_BIN" 2>/dev/null || true
fi
exit 0
EOF

chmod 755 "${PKG_DIR}/DEBIAN/postinst"
dpkg-deb --build "${PKG_DIR}" "${OUTPUT_DEB}"
echo "Debian package created: ${OUTPUT_DEB}"

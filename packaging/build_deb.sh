#!/bin/sh
# Builds dist/captive-autologin_<version>_all.deb (pure Python, depends on python3 only).
set -eu
cd "$(dirname "$0")/.."

VERSION=$(python3 -c "import re;print(re.search(r'__version__ = \"(.+?)\"', open('captive_autologin/__init__.py').read()).group(1))")
PKG=captive-autologin
ROOT=$(mktemp -d)
LIB="$ROOT/usr/lib/$PKG"

mkdir -p "$LIB" "$ROOT/usr/bin" "$ROOT/DEBIAN" "$ROOT/usr/share/doc/$PKG" dist
cp -r captive_autologin "$LIB/"
find "$LIB" -name __pycache__ -type d -prune -exec rm -rf {} +
cp LICENSE "$ROOT/usr/share/doc/$PKG/copyright"

cat > "$ROOT/usr/bin/$PKG" <<'EOF'
#!/bin/sh
PYTHONPATH=/usr/lib/captive-autologin${PYTHONPATH:+:$PYTHONPATH} exec python3 -m captive_autologin "$@"
EOF
chmod 755 "$ROOT/usr/bin/$PKG"

cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.9)
Recommends: libsecret-tools, libnotify-bin
Maintainer: captive-autologin contributors <noreply@users.noreply.github.com>
Homepage: https://github.com/Onny2/captive-autologin
Description: Generic captive portal auto-login
 Detects captive portals and logs in automatically: handles hidden/CSRF
 fields, terms checkboxes, multi-step portals and captcha hooks. Verified
 TLS first, optional insecure fallback. Run "captive-autologin install".
EOF

find "$ROOT" -type d -exec chmod 755 {} +
dpkg-deb --root-owner-group --build "$ROOT" "dist/${PKG}_${VERSION}_all.deb"
rm -rf "$ROOT"
echo "built dist/${PKG}_${VERSION}_all.deb"

#!/bin/sh
# Builds dist/captive-autologin-<version>-macos-<arch>.dmg from a PyInstaller binary.
set -eu
cd "$(dirname "$0")/.."

VERSION=$(python3 -c "import re;print(re.search(r'__version__ = \"(.+?)\"', open('captive_autologin/__init__.py').read()).group(1))")
ARCH=$(uname -m)
STAGE=$(mktemp -d)/captive-autologin

pyinstaller --onefile --clean --noconfirm --paths . --name captive-autologin packaging/entry.py
mkdir -p "$STAGE" dist
cp dist/captive-autologin "$STAGE/"

cat > "$STAGE/Install.command" <<'EOF'
#!/bin/sh
cd "$(dirname "$0")"
xattr -d com.apple.quarantine ./captive-autologin 2>/dev/null || true
exec ./captive-autologin install
EOF
chmod +x "$STAGE/Install.command"
cat > "$STAGE/README.txt" <<'EOF'
Double-click Install.command (right-click > Open the first time: the app is unsigned).
It asks for your portal username/password and starts a background login service.
Remove it later with: ./captive-autologin uninstall
EOF

hdiutil create -volname "captive-autologin" -srcfolder "$STAGE" -ov -format UDZO \
    "dist/captive-autologin-${VERSION}-macos-${ARCH}.dmg"
echo "built dist/captive-autologin-${VERSION}-macos-${ARCH}.dmg"

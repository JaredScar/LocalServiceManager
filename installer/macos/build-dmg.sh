#!/bin/bash
# Builds dist/ServiceDashboard.dmg. Run this on macOS.
set -euo pipefail

VERSION="${1:-1.0.1}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/svcdash-dmg.XXXXXX")"
APP="$STAGE/Service Dashboard.app"
OUT="$ROOT/dist"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/app" "$OUT"

cp "$ROOT/server.js" "$ROOT/config.example.json" "$ROOT/README.md" "$APP/Contents/Resources/app/"
cp -R "$ROOT/lib" "$ROOT/public" "$APP/Contents/Resources/app/"
cp "$ROOT/installer/macos/servicedashboard" "$APP/Contents/MacOS/servicedashboard"
chmod 755 "$APP/Contents/MacOS/servicedashboard"
sed "s/__VERSION__/${VERSION}/g" "$ROOT/installer/macos/Info.plist" > "$APP/Contents/Info.plist"
cp "$ROOT/installer/macos/ReadMe.txt" "$STAGE/Read Me.txt"
ln -s /Applications "$STAGE/Applications"

ICONSET="$STAGE/svcdash.iconset"
mkdir -p "$ICONSET"
sips -z 16 16 "$ROOT/installer/assets/svcdash.png" --out "$ICONSET/icon_16x16.png" >/dev/null
sips -z 32 32 "$ROOT/installer/assets/svcdash.png" --out "$ICONSET/icon_16x16@2x.png" >/dev/null
sips -z 32 32 "$ROOT/installer/assets/svcdash.png" --out "$ICONSET/icon_32x32.png" >/dev/null
sips -z 64 64 "$ROOT/installer/assets/svcdash.png" --out "$ICONSET/icon_32x32@2x.png" >/dev/null
sips -z 128 128 "$ROOT/installer/assets/svcdash.png" --out "$ICONSET/icon_128x128.png" >/dev/null
sips -z 256 256 "$ROOT/installer/assets/svcdash.png" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
sips -z 256 256 "$ROOT/installer/assets/svcdash.png" --out "$ICONSET/icon_256x256.png" >/dev/null
sips -z 512 512 "$ROOT/installer/assets/svcdash.png" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/svcdash.icns"
rm -rf "$ICONSET"

codesign --force --sign - "$APP"

hdiutil create \
  -volname "Service Dashboard" \
  -srcfolder "$STAGE" \
  -ov \
  -format UDZO \
  "$OUT/ServiceDashboard.dmg"

echo "Built $OUT/ServiceDashboard.dmg"

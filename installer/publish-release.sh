#!/bin/bash
# Uploads the files in release-assets/ to the GitHub release for this tag.
set -euo pipefail

tag="${GITHUB_REF_NAME:?}"
notes=$(cat <<EOF
### Windows

Download and run ServiceDashboard-Setup.exe. It installs to C:\\apps\\svcdash and keeps an existing config.json, state folder, collected folder, and logs. Node.js 18 or newer and nssm must already be installed. On a new server, edit C:\\apps\\svcdash\\config.json when setup finishes, then run C:\\apps\\svcdash\\install.ps1.

### Mac

Open ServiceDashboard.dmg and drag Service Dashboard to Applications. Node.js 18 or newer is required. On a Mac the service list and security page use sample data. Site checks are real. Use the Windows setup program on the server to control services.

The first time macOS blocks the app, right-click it, choose Open, and confirm.
EOF
)

if ! gh release view "$tag" >/dev/null 2>&1; then
  gh release create "$tag" --title "$tag" --notes "$notes"
fi

files=()
for name in ServiceDashboard-Setup.exe ServiceDashboard.dmg LocalServiceManager.zip setup.ps1; do
  found="$(find release-assets -type f -name "$name" | head -n 1)"
  if [ -z "$found" ]; then
    echo "Missing $name" >&2
    exit 1
  fi
  files+=("$found")
done

printf 'Uploading:\n'
printf '  %s\n' "${files[@]}"
gh release upload "$tag" "${files[@]}" --clobber

#!/bin/bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "$(uname -s)" != Darwin ]] || ! command -v xcodebuild >/dev/null; then
  echo 'This build requires macOS with Xcode and an iOS 27 SDK.' >&2
  exit 1
fi
build_root="$(mktemp -d)"
trap 'rm -rf "$build_root"' EXIT
xcodebuild -project "$repo_root/ForceDuoApp/ForceDuo.xcodeproj" \
  -target ForceDuo -configuration Release -sdk iphoneos \
  CONFIGURATION_BUILD_DIR="$build_root/products" \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  DEVELOPMENT_TEAM= build
mkdir -p "$build_root/package/Payload" "$repo_root/dist"
cp -R "$build_root/products/ForceDuo.app" "$build_root/package/Payload/"
(cd "$build_root/package" && /usr/bin/zip -qr "$build_root/ForceDuo-LiveContainer.ipa" Payload)
mv "$build_root/ForceDuo-LiveContainer.ipa" "$repo_root/dist/ForceDuo-LiveContainer.ipa"
echo "Created $repo_root/dist/ForceDuo-LiveContainer.ipa"

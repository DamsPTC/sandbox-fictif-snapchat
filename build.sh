#!/bin/bash
set -euo pipefail

cd -- "$(dirname -- "$0")"
if ! command -v xcrun >/dev/null 2>&1; then
    printf '%s\n' 'macOS avec Xcode et son SDK iphoneos est nécessaire.' >&2
    exit 1
fi
QA_SDK_PATH="$(xcrun --sdk iphoneos --show-sdk-path)"
mkdir -p build
xcrun --sdk iphoneos clang \
    -arch arm64 -isysroot "$QA_SDK_PATH" \
    -miphoneos-version-min=12.0 \
    -dynamiclib -fobjc-arc -fblocks -O2 -Wall -Wextra \
    -Wno-deprecated-declarations \
    -framework Foundation -framework UIKit \
    -framework AdSupport -framework Security \
    -framework CoreTelephony -framework DeviceCheck \
    -Wl,-install_name,@executable_path/Frameworks/QAIdentity.dylib \
    -o build/QAIdentity.dylib QAIdentity.m
xcrun lipo build/QAIdentity.dylib -verify_arch arm64
printf '%s\n' 'Créé : build/QAIdentity.dylib (à signer avec l’app).'

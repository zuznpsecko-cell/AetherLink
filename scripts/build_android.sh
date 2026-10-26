#!/usr/bin/env bash
# Reproducible Android build: Rust core (.so for 3 ABIs) + debug APK.
# Requires: Rust targets for Android, cargo-ndk, Android SDK/NDK, Java 17+.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
android="$root/apps/android"
jni="$android/app/src/main/jniLibs"
variant="${1:-debug}"

: "${JAVA_HOME:?JAVA_HOME with JDK 17+ is required}"
: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-}}"
: "${ANDROID_HOME:?ANDROID_HOME is required}"
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  ndk="$(find "$ANDROID_HOME/ndk" -maxdepth 1 -mindepth 1 -type d | sort -r | head -n1)"
  export ANDROID_NDK_HOME="$ndk"
fi
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is required}"

command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 1; }
cargo ndk --version >/dev/null || { echo "cargo-ndk not installed" >&2; exit 1; }

for target in aarch64-linux-android armv7-linux-androideabi x86_64-linux-android; do
  rustup target list --installed | grep -qx "$target" || {
    echo "rustup target add $target" >&2; exit 1; }
done

# The crate lib is `aetherlink_ffi`; hosts load it as `aetherlink_core`
# (same staging rule as the .NET hosts: ffi.dll -> core.dll).
echo "building aetherlink-ffi for arm64-v8a, armeabi-v7a, x86_64"
for abi in arm64-v8a armeabi-v7a x86_64; do
  rm -f "$jni/$abi"/*.so
done
(
  cd "$root"
  cargo ndk --platform 26 \
    -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o "$jni" \
    build --release -p aetherlink-ffi
)

for abi in arm64-v8a armeabi-v7a x86_64; do
  built="$jni/$abi/libaetherlink_ffi.so"
  test -f "$built" || { echo "missing $built" >&2; exit 1; }
  mv -f "$built" "$jni/$abi/libaetherlink_core.so"
done

chmod +x "$android/gradlew" 2>/dev/null || true
task="assemble$(echo "${variant:0:1}" | tr '[:lower:]' '[:upper:]')${variant:1}"
(cd "$android" && ./gradlew "$task" --console=plain)

apk="$android/app/build/outputs/apk/$variant/app-$variant.apk"
test -f "$apk" || { echo "APK not found: $apk" >&2; exit 1; }
echo
echo "APK: $apk"

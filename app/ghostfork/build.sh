#!/bin/bash
# Build ghostfork (dev.yt.ghostroot) without Gradle.
# Needs: ANDROID_SDK with build-tools (aapt2, d8, zipalign, apksigner) and
#        platforms/android-34/android.jar, plus a JDK 17+.
set -eu
SDK="${ANDROID_SDK:-$HOME/Library/Android/sdk}"
BT="${BUILD_TOOLS:-$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)}"
PLATFORM="${PLATFORM_JAR:-$SDK/platforms/android-34/android.jar}"
OUT=build; APK=GhostRoot-unsigned.apk; SIGNED=GhostRoot.apk

[ -x "$BT/aapt2" ] || { echo "missing aapt2 in $BT"; exit 1; }
[ -f "$PLATFORM" ] || { echo "missing android.jar at $PLATFORM"; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT/classes" "$OUT/dex"

# 1) compile against the platform jar (Java 8 bytecode for d8)
javac -source 8 -target 8 -bootclasspath "$PLATFORM" -d "$OUT/classes" \
    src/dev/yt/ghostroot/MainActivity.java

# 2) dex
"$BT/d8" --lib "$PLATFORM" --min-api 26 --output "$OUT/dex" \
    $(find "$OUT/classes" -name "*.class")

# 3) resources + manifest (no res/ used, but aapt2 still has to binary-pack the manifest)
"$BT/aapt2" link -o "$OUT/base.apk" -I "$PLATFORM" \
    --manifest AndroidManifest.xml --min-sdk-version 26 --target-sdk-version 34

# 4) drop the dex in and align/sign
( cd "$OUT" && zip -q -j base.apk dex/classes.dex )
"$BT/zipalign" -f 4 "$OUT/base.apk" "$OUT/$APK"
[ -f keystore.jks ] || keytool -genkeypair -keystore keystore.jks -storepass ghostroot \
    -keypass ghostroot -alias ghost -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=GhostRoot"
"$BT/apksigner" sign --ks keystore.jks --ks-pass pass:ghostroot --out "$SIGNED" "$OUT/$APK"
echo "built: $SIGNED"
echo "install: adb install -r $SIGNED"
